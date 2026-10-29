package app.washerctl

import android.content.Context
import java.net.URLDecoder
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock
import org.json.JSONArray
import org.json.JSONObject

class HttpError(val status: Int, message: String) : Exception(message)

class ApiResponse(val status: Int, val body: String)

/**
 * On-device port of web/server.py. Handles the same /api/... routes the web UI calls;
 * requests arrive from the WebView through bridge.js instead of over HTTP.
 * Called on background threads.
 */
class WasherApi(context: Context) {
    private val store = Store(context)
    private val net = Net(context)

    @Volatile private var lastStatus: JSONObject? = null
    @Volatile private var lastStatusTime = 0L

    private val discoveryLock = ReentrantLock()
    @Volatile private var lastFailedDiscovery = 0L

    private val programmesData: JSONObject by lazy { JSONObject(store.asset("programmes.json") ?: "{}") }

    fun handle(method: String, path: String, body: String): ApiResponse = try {
        val route = path.substringBefore('?')
        val q = parseQuery(path.substringAfter('?', ""))
        val res: Any = when {
            method == "GET" && route == "/api/config" -> getConfig()
            method == "POST" && route == "/api/config" -> setConfig(json(body))
            method == "GET" && route == "/api/status" -> getStatus(q["force"].let { it == "true" || it == "1" })
            method == "POST" && route == "/api/start" -> start(json(body))
            method == "POST" && route == "/api/dual-start" -> dualStart(json(body))
            method == "POST" && route == "/api/pause" -> pauseResume(pause = true)
            method == "POST" && route == "/api/resume" -> pauseResume(pause = false)
            method == "POST" && route == "/api/stop" -> stop(q.reqInt("prnm"))
            method == "GET" && route == "/api/programmes" -> getProgrammes()
            method == "GET" && route == "/api/favourites" -> store.loadFavourites()
            method == "POST" && route == "/api/favourites" -> addFavourite(json(body))
            method == "DELETE" && route.startsWith("/api/favourites/") ->
                deleteFavourite(URLDecoder.decode(route.removePrefix("/api/favourites/"), "UTF-8"))
            method == "GET" && route == "/api/probe" -> probe(q.req("ip"), q.req("key"))
            method == "POST" && route == "/api/discover" -> discover(q["timeout"]?.toDoubleOrNull() ?: 15.0)
            else -> throw HttpError(404, "Not Found")
        }
        ApiResponse(200, res.toString())
    } catch (e: HttpError) {
        ApiResponse(e.status, JSONObject().put("detail", e.message).toString())
    } catch (e: Exception) {
        ApiResponse(500, JSONObject().put("detail", "${e.javaClass.simpleName}: ${e.message}").toString())
    }

    /** On app start: if a key is known but no IP, look for the washer. Returns true if found. */
    fun autoDiscoverIfNeeded(): Boolean {
        val cfg = store.loadConfig()
        if (cfg.optString("key").isEmpty() || cfg.optString("ip").isNotEmpty()) return false
        return rediscover("") != null
    }

    // ---- helpers ----

    private fun json(body: String): JSONObject =
        try { JSONObject(body) } catch (e: Exception) { throw HttpError(422, "Invalid JSON body") }

    private fun parseQuery(qs: String): Map<String, String> =
        qs.split('&').filter { it.isNotEmpty() }.associate {
            URLDecoder.decode(it.substringBefore('='), "UTF-8") to URLDecoder.decode(it.substringAfter('=', ""), "UTF-8")
        }

    private fun Map<String, String>.req(name: String) = this[name] ?: throw HttpError(422, "Missing query parameter: $name")
    private fun Map<String, String>.reqInt(name: String) =
        req(name).toIntOrNull() ?: throw HttpError(422, "Query parameter $name must be an integer")

    private fun JSONObject.optIntOrNull(name: String): Int? =
        if (!has(name) || isNull(name)) null else try { getInt(name) } catch (e: Exception) { throw HttpError(422, "$name must be an integer") }
    private fun JSONObject.reqInt(name: String): Int = optIntOrNull(name) ?: throw HttpError(422, "Missing field: $name")
    private fun JSONObject.intOr(name: String, def: Int) = optIntOrNull(name) ?: def
    private fun JSONObject.strOr(name: String, def: String) = if (!has(name) || isNull(name)) def else getString(name)

    // ---- discovery ----

    /**
     * Find the washer at a new IP after [failedIp] stopped answering. Only one search runs at a
     * time, and after a failed search we wait 30 s before trying again, so a switched-off washer
     * doesn't trigger a network scan on every 5 s status poll.
     */
    private fun rediscover(failedIp: String): String? = discoveryLock.withLock {
        val cfg = store.loadConfig()
        val current = cfg.optString("ip")
        if (current.isNotEmpty() && current != failedIp) return current  // another request already found it
        if (System.currentTimeMillis() - lastFailedDiscovery < 30_000) return null

        val mac = cfg.optString("mac")
        val key = cfg.optString("key")
        val found = (if (mac.isNotEmpty()) net.discoverUdp(mac, 8000)?.first else null)
            ?: (if (key.isNotEmpty()) net.lanScan(key) else null)
        if (found == null) {
            lastFailedDiscovery = System.currentTimeMillis()
            return null
        }
        cfg.put("ip", found)
        store.saveConfig(cfg)
        found
    }

    // ---- config ----

    private fun getConfig(): JSONObject {
        val cfg = store.loadConfig()
        return JSONObject()
            .put("ip", cfg.optString("ip"))
            .put("key", cfg.optString("key"))
            .put("protocol", cfg.optString("protocol", "wifible"))
    }

    private fun setConfig(body: JSONObject): JSONObject {
        if (!body.has("ip") || !body.has("key")) throw HttpError(422, "ip and key are required")
        val cfg = store.loadConfig()  // keep other fields such as the MAC used for discovery
        cfg.put("ip", body.getString("ip"))
        cfg.put("key", body.getString("key"))
        cfg.put("protocol", body.strOr("protocol", "wifible"))
        store.saveConfig(cfg)
        lastStatus = null
        lastFailedDiscovery = 0
        return JSONObject().put("ok", true)
    }

    // ---- status ----

    private fun getStatus(force: Boolean): JSONObject {
        val cfg = store.loadConfig()
        val ip = cfg.optString("ip")
        val key = cfg.optString("key")
        if (ip.isEmpty() || key.isEmpty()) throw HttpError(400, "Washer IP and key not configured")

        val cached = lastStatus
        if (!force && cached != null && System.currentTimeMillis() - lastStatusTime < 3000) return cached

        val raw = try {
            net.get(CandyCrypto.readUrl(ip))
        } catch (e: Exception) {
            val newIp = rediscover(ip) ?: throw HttpError(502, "Cannot reach washer at $ip and re-discovery failed")
            try { net.get(CandyCrypto.readUrl(newIp)) } catch (e2: Exception) {
                throw HttpError(502, "Cannot reach washer at $newIp: ${e2.message}")
            }
        }
        val decoded = try { CandyCrypto.decodeStatus(raw, key) } catch (e: Exception) {
            throw HttpError(502, "Failed to decrypt/decode status: ${e.message}")
        }
        lastStatus = decoded
        lastStatusTime = System.currentTimeMillis()
        return decoded
    }

    // ---- commands ----

    private fun sendCommand(cmd: String): JSONObject {
        val cfg = store.loadConfig()
        val ip = cfg.optString("ip")
        val key = cfg.optString("key")
        if (ip.isEmpty() || key.isEmpty()) throw HttpError(400, "Not configured")
        val raw = try {
            net.get(CandyCrypto.writeUrl(ip, cmd, key))
        } catch (e: Exception) {
            val newIp = rediscover(ip) ?: throw HttpError(502, "Cannot reach washer at $ip and re-discovery failed")
            try { net.get(CandyCrypto.writeUrl(newIp, cmd, key)) } catch (e2: Exception) {
                throw HttpError(502, "Cannot reach washer at $newIp: ${e2.message}")
            }
        }
        lastStatusTime = 0
        return try { JSONObject(CandyCrypto.xorDecrypt(raw, key)) } catch (_: Exception) {
            JSONObject().put("raw_response", raw)
        }
    }

    private fun protocol() = store.loadConfig().optString("protocol", "wifible")

    private fun start(b: JSONObject): JSONObject {
        if (protocol() == "dual") throw HttpError(400, "Use /api/dual-start for dual protocol")
        val cmd = CandyCrypto.wifibleStart(
            prnm = b.reqInt("prnm"),
            prcode = b.reqInt("prcode"),
            prstr = b.strOr("prstr", "Program"),
            temp = b.optIntOrNull("temp"),
            soil = b.intOr("soil", 0),
            spinRpm = b.optIntOrNull("spin_rpm"),
            optmsk1 = b.intOr("optmsk1", 0),
            optmsk2 = b.intOr("optmsk2", 0),
            lang = b.intOr("lang", 1),
            steam = b.intOr("steam", 0),
            dry = b.intOr("dry", 0),
            extraDose = b.intOr("extra_dose", 0),
            recipeId = b.strOr("recipe_id", "0"),
            delaySteps = b.intOr("delay_steps", 0),
        )
        return sendCommand(cmd)
    }

    private fun dualStart(b: JSONObject): JSONObject {
        val cmd = CandyCrypto.dualStart(
            prnm = b.reqInt("prnm"),
            defaultTemp = b.reqInt("default_temp"),
            defaultSpinRpm = b.reqInt("default_spin_rpm"),
            defaultSoil = b.reqInt("default_soil"),
            temp = b.optIntOrNull("temp"),
            spinRpm = b.optIntOrNull("spin_rpm"),
            soil = b.optIntOrNull("soil"),
            optmsk = b.intOr("optmsk", 0),
            steam = b.intOr("steam", 0),
            dry = b.optIntOrNull("dry"),
            recipeId = b.strOr("recipe_id", "0"),
            delaySteps = b.intOr("delay_steps", 0),
            dryOnly = b.optBoolean("dry_only", false),
            prcode = b.optIntOrNull("prcode"),
        )
        return sendCommand(cmd)
    }

    private fun pauseResume(pause: Boolean): JSONObject {
        if (protocol() == "dual") {
            throw HttpError(400, "Dual protocol does not support ${if (pause) "pause" else "resume"}")
        }
        return sendCommand(if (pause) CandyCrypto.wifiblePause() else CandyCrypto.wifibleResume())
    }

    private fun stop(prnm: Int): JSONObject =
        sendCommand(if (protocol() == "dual") CandyCrypto.dualStop(prnm) else CandyCrypto.wifibleStop(prnm))

    // ---- programmes ----

    private fun getProgrammes(): JSONObject {
        val proto = protocol()
        // Prefer the real programme list from the cloud (saved by bootstrap.py --save)
        val demo = if (proto == "dual" && programmesData.has("washer_dryer_dual_demo")) {
            programmesData.getJSONObject("washer_dryer_dual_demo").optJSONArray("programmes")
        } else {
            programmesData.optJSONObject("washer_dryer_wifible_demo")?.optJSONArray("programmes")
        }
        val progs = store.asset("my_programmes.json")?.let { JSONArray(it) } ?: demo ?: JSONArray()
        return JSONObject()
            .put("protocol", proto)
            .put("programmes", progs)
            .put("option_bits", programmesData.optJSONObject("option_bits_OptMsk1") ?: JSONObject())
            .put("steam_values", programmesData.optJSONObject("steam_values") ?: JSONObject())
            .put("dry_values", programmesData.optJSONObject("dry_values_wifible") ?: JSONObject())
    }

    // ---- favourites ----

    private fun addFavourite(b: JSONObject): JSONObject {
        val name = b.optString("name").ifEmpty { throw HttpError(422, "Missing field: name") }
        val fav = JSONObject()
            .put("id", "fav_${System.currentTimeMillis()}")
            .put("name", name)
            .put("prnm", b.reqInt("prnm"))
            .put("prcode", b.reqInt("prcode"))
            .put("settings", b.optJSONObject("settings") ?: throw HttpError(422, "Missing field: settings"))
        synchronized(store) {
            val favs = store.loadFavourites()
            val updated = JSONArray().put(fav)
            for (i in 0 until favs.length()) updated.put(favs.get(i))
            store.saveFavourites(updated)
        }
        return fav
    }

    private fun deleteFavourite(id: String): JSONObject {
        synchronized(store) {
            val favs = store.loadFavourites()
            val kept = JSONArray()
            for (i in 0 until favs.length()) {
                val f = favs.getJSONObject(i)
                if (f.optString("id") != id) kept.put(f)
            }
            store.saveFavourites(kept)
        }
        return JSONObject().put("ok", true)
    }

    // ---- probe / discover ----

    private fun probe(ip: String, key: String): JSONObject {
        val raw = try { net.get(CandyCrypto.readUrl(ip), 5000) } catch (e: Exception) {
            return JSONObject().put("ok", false).put("error", "Cannot reach $ip: ${e.message ?: e.javaClass.simpleName}")
        }
        return try {
            JSONObject().put("ok", true).put("status", CandyCrypto.decodeStatus(raw, key))
        } catch (e: Exception) {
            JSONObject().put("ok", false).put("error", "Key may be wrong: ${e.message}")
        }
    }

    private fun discover(timeoutS: Double): JSONObject {
        if (timeoutS > 60) throw HttpError(422, "timeout must be <= 60")
        val cfg = store.loadConfig()
        val mac = cfg.optString("mac")
        if (mac.isEmpty()) throw HttpError(400, "No MAC address in config — run bootstrap.py --save first")
        val result = discoveryLock.withLock { net.discoverUdp(mac, (timeoutS * 1000).toLong()) }
            ?: return JSONObject().put("ok", false).put("error", "No broadcast received within ${timeoutS}s")
        cfg.put("ip", result.first)
        store.saveConfig(cfg)
        return JSONObject().put("ok", true).put("ip", result.first)
    }
}
