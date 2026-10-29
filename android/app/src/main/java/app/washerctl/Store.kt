package app.washerctl

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

/**
 * Persistent config and favourites (replaces config.json / favourites.json on the server).
 * On first launch they are seeded from the copies bundled into the APK's assets at build time.
 */
class Store(context: Context) {
    private val ctx = context.applicationContext
    private val prefs = ctx.getSharedPreferences("washer", Context.MODE_PRIVATE)

    fun asset(name: String): String? =
        try { ctx.assets.open(name).use { it.readBytes().toString(Charsets.UTF_8) } } catch (_: Exception) { null }

    @Synchronized
    fun loadConfig(): JSONObject {
        prefs.getString(KEY_CONFIG, null)?.let { return JSONObject(it) }
        val seeded = asset("config.json")?.let { runCatching { JSONObject(it) }.getOrNull() }
            ?: JSONObject().put("ip", "").put("key", "").put("protocol", "wifible")
        saveConfig(seeded)
        return seeded
    }

    @Synchronized
    fun saveConfig(cfg: JSONObject) {
        prefs.edit().putString(KEY_CONFIG, cfg.toString()).apply()
    }

    @Synchronized
    fun loadFavourites(): JSONArray {
        prefs.getString(KEY_FAVOURITES, null)?.let { return JSONArray(it) }
        val seeded = asset("favourites.json")?.let { runCatching { JSONArray(it) }.getOrNull() } ?: JSONArray()
        saveFavourites(seeded)
        return seeded
    }

    @Synchronized
    fun saveFavourites(favs: JSONArray) {
        prefs.edit().putString(KEY_FAVOURITES, favs.toString()).apply()
    }

    private companion object {
        const val KEY_CONFIG = "config"
        const val KEY_FAVOURITES = "favourites"
    }
}
