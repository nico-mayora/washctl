package app.washerctl

import org.json.JSONArray
import org.json.JSONObject

/**
 * Port of web/candy_crypto.py: XOR+hex payload scheme, command strings for the
 * "wifible" and "dual" washer protocols, and the status decoder.
 * Builds strings only; sending them is up to the caller.
 */
object CandyCrypto {
    private const val HEX = "0123456789ABCDEF"

    fun xorEncrypt(plaintext: String, key: String): String {
        require(key.isNotEmpty()) { "empty key" }
        val m = plaintext.toByteArray(Charsets.UTF_8)
        val k = key.toByteArray(Charsets.UTF_8)
        val sb = StringBuilder(m.size * 2)
        for (i in m.indices) {
            val b = (m[i].toInt() xor k[i % k.size].toInt()) and 0xFF
            sb.append(HEX[b ushr 4]).append(HEX[b and 0xF])
        }
        return sb.toString()
    }

    fun xorDecrypt(hexPayload: String, key: String): String {
        require(key.isNotEmpty()) { "empty key" }
        val h = hexPayload.filterNot { it.isWhitespace() }
        require(h.length % 2 == 0) { "odd-length hex payload" }
        val k = key.toByteArray(Charsets.UTF_8)
        val out = ByteArray(h.length / 2)
        for (i in out.indices) {
            val hi = Character.digit(h[2 * i], 16)
            val lo = Character.digit(h[2 * i + 1], 16)
            require(hi >= 0 && lo >= 0) { "non-hexadecimal character in payload" }
            out[i] = (((hi shl 4) or lo) xor k[i % k.size].toInt()).toByte()
        }
        return String(out, Charsets.UTF_8)
    }

    // ---- URLs ----

    fun readUrl(ip: String) = "http://$ip/http-read.json?encrypted=1"

    fun writeUrl(ip: String, params: String, key: String) =
        "http://$ip/http-write.json?encrypted=1&data=${xorEncrypt(params, key)}"

    private fun join(p: List<Pair<String, Any>>) = p.joinToString("&") { "${it.first}=${it.second}" }

    // ---- wifible commands ----

    fun wifibleStart(
        prnm: Int, prcode: Int, prstr: String = "Program", temp: Int? = null,
        soil: Int = 0, spinRpm: Int? = null, optmsk1: Int = 0, optmsk2: Int = 0,
        lang: Int = 1, steam: Int = 0, dry: Int = 0, extraDose: Int = 0,
        recipeId: String = "0", delaySteps: Int = 0, checkup: Boolean = false,
    ): String {
        val p = mutableListOf<Pair<String, Any>>(
            "StSt" to 1, "DelVl" to delaySteps, "PrNm" to prnm, "PrCode" to prcode, "PrStr" to prstr,
        )
        if (temp != null) p += "TmpTgt" to temp
        p += "SLevTgt" to (if (soil == 255) 0 else soil)
        if (spinRpm != null && spinRpm != 255) p += "SpdTgt" to Math.floorDiv(spinRpm, 100)
        p += listOf(
            "OptMsk1" to optmsk1, "OptMsk2" to optmsk2, "Lang" to lang, "Stm" to steam, "Dry" to dry,
            "ED" to extraDose, "RecipeId" to recipeId, "StartCheckUp" to (if (checkup) 1 else 0),
            "DispTestOn" to 1,
        )
        return "Write=1&" + join(p)
    }

    fun wifibleStop(currentPrnm: Int?, delayed: Boolean = false): String {
        var s = "Write=1&StSt=0"
        if (currentPrnm != null) s += "&PrNm=$currentPrnm"
        if (delayed) s += "&DelVl=0"
        return s
    }

    /** The 'encrypted=0&' prefix is part of the (encrypted) payload, as in the official app. */
    fun wifiblePause() = "encrypted=0&Pa=1"
    fun wifibleResume() = "encrypted=0&Pa=0"

    // ---- dual commands ----

    fun dualStart(
        prnm: Int, defaultTemp: Int, defaultSpinRpm: Int, defaultSoil: Int,
        temp: Int? = null, spinRpm: Int? = null, soil: Int? = null, optmsk: Int = 0,
        steam: Int = 0, dry: Int? = null, recipeId: String = "0", delaySteps: Int = 0,
        dryOnly: Boolean = false, prcode: Int? = null,
    ): String {
        val s = StringBuilder("Write=1&Pa=0&Sel=0&PrNm=$prnm")
        if (prcode != null) s.append("&PrCode=$prcode")
        s.append(if (delaySteps > 0) "&DelMd=1&DelVl=$delaySteps" else "&StSt=1")
        if (!dryOnly) {
            val t = temp ?: defaultTemp
            if (t != defaultTemp && t != 255) s.append("&TmpTgt=$t&TmpDf=$defaultTemp")
            var sl = soil ?: defaultSoil
            if (sl != defaultSoil && sl != 255) {
                if (t == 90 && sl == 1) sl = 2
                s.append("&SLevTgt=$sl")
            }
            val sp = spinRpm ?: defaultSpinRpm
            if (sp != defaultSpinRpm && sp != 255) {
                s.append("&SpdTgt=${Math.floorDiv(sp, 100)}&SpdDef=${Math.floorDiv(defaultSpinRpm, 100)}")
            }
        }
        if (optmsk > 0) s.append("&OptMsk=$optmsk")
        val d = dry ?: 0
        s.append("&Stm=$steam&Dry=$d&Option=$d")
        s.append("&RecipeId=$recipeId&CheckUpState=0")
        return s.toString()
    }

    fun dualStop(currentPr: Int) = "Write=1&StSt=0&DelMd=0&PrNm=$currentPr"

    // ---- status ----

    private val MACHINE_MODE = mapOf(
        0 to "no state", 1 to "selection", 2 to "running", 3 to "paused",
        4 to "delayed start (selection)", 5 to "delayed start (counting down)", 6 to "error", 7 to "finished",
    )
    private val PHASE = mapOf(
        0 to "none", 1 to "prewash", 2 to "wash", 3 to "rinse", 4 to "last rinse", 5 to "end",
        6 to "drying", 7 to "error", 8 to "steam", 9 to "good-night pause", 255 to "n/a",
    )
    private val OPTION_BITS = linkedMapOf(
        1 to "prewash", 2 to "hygiene", 4 to "anti-crease", 8 to "good night", 16 to "rinse+1",
        32 to "rinse+2", 64 to "rinse+3", 128 to "aquaplus",
    )

    /** Decode an http-read.json reply (hex XOR'd with [key]) into the same JSON shape as server.py. */
    fun decodeStatus(body: String, key: String): JSONObject {
        val root = JSONObject(xorDecrypt(body, key))
        val st = root.optJSONObject("statusLavatrice") ?: root

        fun i(name: String): Int? {
            if (!st.has(name) || st.isNull(name)) return null
            return when (val v = st.get(name)) {
                is Number -> v.toInt()
                is Boolean -> if (v) 1 else 0
                is String -> v.trim().toIntOrNull()
                else -> null
            }
        }
        fun n(v: Any?): Any = v ?: JSONObject.NULL
        fun pair(code: Int?, names: Map<Int, String>) = JSONArray().put(n(code)).put(n(code?.let { names[it] }))

        val out = JSONObject()
        out.put("raw", st)
        out.put("machine_mode", pair(i("MachMd"), MACHINE_MODE))
        out.put("phase", pair(i("PrPh"), PHASE))
        out.put("program_number", n(i("PrNm") ?: i("Pr")))
        out.put("program_code", n(i("PrCode")))
        out.put("temperature_C", n(i("Temp")))
        val sp = i("SpinSp")
        out.put("spin_rpm", n(sp?.let { if (it < 100) it * 100 else it }))
        out.put("soil_level", n(i("SLevel")))
        out.put("remaining_time_s", n(i("RemTime")))
        out.put("delay_value", n(i("DelVal")))
        out.put("remote_control_enabled", if (st.has("WiFiStatus")) {
            when (val w = st.opt("WiFiStatus")) {
                is String -> w == "1" || w == "true"
                is Number -> w.toDouble() == 1.0
                is Boolean -> w
                else -> false
            }
        } else JSONObject.NULL)
        out.put("error_code", n(st.opt("Err")))
        var mask = 0
        for (k in 1..8) if ((i("Opt$k") ?: 0) != 0) mask = mask or (1 shl (k - 1))
        out.put("options_mask1", mask)
        out.put("options", JSONArray(OPTION_BITS.filterKeys { mask and it != 0 }.values.toList()))
        out.put("steam", n(i("Steam")))
        out.put("dry_type", n(i("DryT")))
        out.put("recipe_id", n(st.opt("RecipeId")))
        return out
    }
}
