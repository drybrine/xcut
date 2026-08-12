package com.drybrine.xcutandroid

import android.app.Activity
import android.graphics.Typeface
import android.os.Bundle
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import rikka.shizuku.Shizuku

data class Neighbor(val ip: String, val dev: String, val mac: String, val state: String)

class MainActivity : Activity() {

    private val scope = CoroutineScope(Dispatchers.Main)
    private val permissionCode = 1001

    private lateinit var statusView: TextView
    private lateinit var capView: TextView
    private lateinit var listView: LinearLayout
    private lateinit var logView: TextView

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

        statusView = TextView(this).apply {
            text = "Shizuku: check dulu"
        }
        capView = TextView(this).apply {
            typeface = Typeface.MONOSPACE
        }
        logView = TextView(this).apply {
            typeface = Typeface.MONOSPACE
            textSize = 11f
        }
        listView = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
        }

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
                addView(Button(this@MainActivity).apply {
                    text = "Scan (ip neigh)"
                    setOnClickListener { scan() }
                })
                addView(listView)
                addView(logView)
            })
        }
        setContentView(scroll)
    }

    override fun onDestroy() {
        super.onDestroy()
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
            val caps = ShizukuShell.capabilities()
            statusView.text = "Shizuku binder: ${if (Shizuku.pingBinder()) "LIVE" else "MATI"}"
            capView.text = buildString {
                append("uid shell: ").append(caps["uid"]).append('\n')
                append("CapEff: ").append(caps["cap_eff"]).append('\n')
                append("CAP_NET_RAW  : ").append(caps["CAP_NET_RAW"]).append('\n')
                append("CAP_NET_ADMIN: ").append(caps["CAP_NET_ADMIN"])
            }
            appendLog("cekap: ${caps["CAP_NET_ADMIN"] == "true"}")
        }
    }

    private fun scan() {
        scope.launch {
            val r = ShizukuShell.run("ip neigh")
            listView.removeAllViews()
            appendLog("scan -> exit ${r.exit}")
            if (r.stderr.isNotBlank()) appendLog(r.stderr)
            parseNeigh(r.stdout).forEach { addRow(it) }
            if (r.stdout.isBlank()) appendLog("(neighbor table kosong)")
        }
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
            val r = ShizukuShell.run("ip neigh replace $ip lladdr 00:00:00:00:00:00 dev $dev nud permanent")
            appendLog("cut $ip -> exit ${r.exit} ${r.stderr.trim()}")
        }
    }

    private fun uncut(ip: String, dev: String) {
        scope.launch {
            val r = ShizukuShell.run("ip neigh del $ip dev $dev")
            appendLog("uncut $ip -> exit ${r.exit} ${r.stderr.trim()}")
        }
    }

    private fun appendLog(s: String) {
        logView.append("$s\n")
    }
}
