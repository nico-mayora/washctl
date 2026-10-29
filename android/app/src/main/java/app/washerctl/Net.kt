package app.washerctl

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.wifi.WifiManager
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.HttpURLConnection
import java.net.Inet4Address
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.net.SocketTimeoutException
import java.net.URL
import java.util.concurrent.ExecutorCompletionService
import java.util.concurrent.Executors
import org.json.JSONObject

/** LAN HTTP and washer discovery (port of server.py's washer_get and web/discover.py). */
class Net(context: Context) {
    private val ctx = context.applicationContext
    private val cm = ctx.getSystemService(ConnectivityManager::class.java)

    /**
     * Network to reach the washer on. Normally the system default. But if Wi-Fi is up
     * without internet, Android may route everything over mobile data, so in that case
     * pin LAN traffic to Wi-Fi.
     */
    private fun lanNetwork(): Network? {
        val active = cm.activeNetwork
        val caps = active?.let { cm.getNetworkCapabilities(it) }
        if (caps != null && (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) ||
                caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) ||
                caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN))) return null
        @Suppress("DEPRECATION")
        return cm.allNetworks.firstOrNull {
            cm.getNetworkCapabilities(it)?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true
        }
    }

    /** GET [url] and return the trimmed body. Throws on network errors and HTTP >= 400. */
    fun get(url: String, timeoutMs: Int = 8000): String {
        val u = URL(url)
        val conn = (lanNetwork()?.openConnection(u) ?: u.openConnection()) as HttpURLConnection
        try {
            conn.connectTimeout = timeoutMs
            conn.readTimeout = timeoutMs
            conn.useCaches = false
            conn.setRequestProperty("Connection", "close")
            val code = conn.responseCode
            if (code >= 400) throw IOException("HTTP $code from ${u.host}")
            return conn.inputStream.use { it.readBytes() }.toString(Charsets.UTF_8).trim()
        } finally {
            conn.disconnect()
        }
    }

    // ---- UDP broadcast discovery (port 55555) ----

    /**
     * Listen for the washer's UDP broadcast. Returns (ip, mac) or null on timeout.
     * Bytes 60..92 of the packet hold ASCII text whose chars 1..13 are the MAC.
     */
    fun discoverUdp(mac: String?, timeoutMs: Long): Pair<String, String>? {
        val target = mac?.replace(":", "")?.replace("-", "")?.lowercase()
        val wifi = ctx.getSystemService(WifiManager::class.java)
        // Some devices drop broadcast packets unless a multicast lock is held.
        val lock = wifi?.createMulticastLock("washer-discovery")?.apply {
            setReferenceCounted(false); acquire()
        }
        try {
            DatagramSocket(null).use { sock ->
                sock.reuseAddress = true
                sock.broadcast = true
                sock.bind(InetSocketAddress(55555))
                val deadline = System.currentTimeMillis() + timeoutMs
                val buf = ByteArray(4096)
                while (true) {
                    val remaining = deadline - System.currentTimeMillis()
                    if (remaining <= 0) return null
                    sock.soTimeout = remaining.toInt()
                    val pkt = DatagramPacket(buf, buf.size)
                    try {
                        sock.receive(pkt)
                    } catch (e: SocketTimeoutException) {
                        return null
                    }
                    val pktMac = macFromPacket(pkt.data.copyOf(pkt.length)) ?: continue
                    if (target != null && pktMac != target) continue
                    val ip = pkt.address?.hostAddress ?: continue
                    return ip to pktMac
                }
            }
        } finally {
            lock?.release()
        }
    }

    // ---- LAN scan fallback ----

    private fun localPrefixes(): List<String> {
        val prefixes = linkedSetOf<String>()
        val net = lanNetwork() ?: cm.activeNetwork
        net?.let { cm.getLinkProperties(it) }?.linkAddresses?.forEach { la ->
            val a = la.address
            if (a is Inet4Address && !a.isLoopbackAddress) prefixes += a.hostAddress!!.substringBeforeLast('.')
        }
        if (prefixes.isEmpty()) {
            try {
                for (ni in NetworkInterface.getNetworkInterfaces()) {
                    if (!ni.isUp || ni.isLoopback) continue
                    if (listOf("docker", "br-", "veth", "virbr", "rmnet", "dummy").any { ni.name.startsWith(it) }) continue
                    for (a in ni.inetAddresses) {
                        if (a is Inet4Address && !a.isLoopbackAddress) prefixes += a.hostAddress!!.substringBeforeLast('.')
                    }
                }
            } catch (_: Exception) {
            }
        }
        return prefixes.toList().ifEmpty { listOf("192.168.1") }
    }

    /** Try http-read.json on every host of the local /24(s); return the IP whose reply decrypts with [key]. */
    fun lanScan(key: String, timeoutPerHostMs: Int = 2000): String? {
        val pool = Executors.newFixedThreadPool(64)
        try {
            val ecs = ExecutorCompletionService<String?>(pool)
            var submitted = 0
            for (prefix in localPrefixes()) {
                for (host in 1..254) {
                    val ip = "$prefix.$host"
                    ecs.submit {
                        try {
                            val raw = get(CandyCrypto.readUrl(ip), timeoutPerHostMs)
                            if (JSONObject(CandyCrypto.xorDecrypt(raw, key)).length() > 0) ip else null
                        } catch (_: Exception) {
                            null
                        }
                    }
                    submitted++
                }
            }
            repeat(submitted) { ecs.take().get()?.let { return it } }
            return null
        } finally {
            pool.shutdownNow()
        }
    }

    companion object {
        /** Mirrors discover._extract_mac_from_packet (non-ASCII bytes are dropped, like errors="ignore"). */
        fun macFromPacket(data: ByteArray): String? {
            if (data.size < 92) return null
            val text = String(data.copyOfRange(60, 92).filter { it >= 0 }.map { it.toInt().toChar() }.toCharArray())
            if (text.length < 13) return null
            return text.substring(1, 13).lowercase()
        }
    }
}
