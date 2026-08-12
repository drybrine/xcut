package com.drybrine.xcutandroid

import java.io.BufferedReader
import java.io.BufferedWriter
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.InetSocketAddress
import java.net.Socket
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Client for the xcutd daemon (127.0.0.1:28888) - the raw-socket ARP engine
 * started as the shell uid via our built-in adb bootstrap.
 */
class XcutDaemon {

    data class DaemonResult(val exit: Int, val lines: List<String>, val message: String)

    companion object {
        const val PORT = 28888
    }

    private var sock: Socket? = null
    private var reader: BufferedReader? = null
    private var writer: BufferedWriter? = null

    suspend fun isUp(): Boolean = withContext(Dispatchers.IO) {
        try {
            Socket().use { it.connect(InetSocketAddress("127.0.0.1", PORT), 500); true }
        } catch (e: Exception) {
            false
        }
    }

    suspend fun connect(): Boolean = withContext(Dispatchers.IO) {
        try {
            val s = Socket()
            s.connect(InetSocketAddress("127.0.0.1", PORT), 2000)
            s.soTimeout = 60000
            val r = BufferedReader(InputStreamReader(s.getInputStream()))
            val w = BufferedWriter(OutputStreamWriter(s.getOutputStream()))
            w.write("ping\n")
            w.flush()
            val pong = r.readLine()
            if (pong == "PONG") {
                sock = s; reader = r; writer = w
                true
            } else {
                s.close()
                false
            }
        } catch (e: Exception) {
            false
        }
    }

    private fun cmd(line: String, timeoutMs: Long = 30000): DaemonResult {
        val s = sock ?: throw IllegalStateException("daemon not connected")
        s.soTimeout = timeoutMs.toInt()
        writer!!.write(line + "\n")
        writer!!.flush()
        val lines = mutableListOf<String>()
        val t0 = System.currentTimeMillis()
        while (true) {
            val l = reader!!.readLine() ?: break
            if (l == "OK" || l == "ERR" || l == "STOPPED") {
                return if (l == "OK") DaemonResult(0, lines, "ok")
                else if (l == "STOPPED") DaemonResult(0, lines, "stopped")
                else DaemonResult(1, lines, "error")
            }
            if (l.startsWith("ERR")) return DaemonResult(1, lines, l)
            lines.add(l)
            if (System.currentTimeMillis() - t0 > timeoutMs) break
        }
        return DaemonResult(-1, lines, "timeout")
    }

    suspend fun scan(): List<Neighbor> = withContext(Dispatchers.IO) {
        if (!connect()) return@withContext emptyList()
        val r = cmd("scan", 45000)
        r.lines.mapNotNull { line ->
            val parts = line.trim().split(' ')
            if (parts.size == 2) Neighbor(parts[0], "wlan", parts[1], "dmn") else null
        }
    }

    suspend fun spoof(ip: String) {
        withContext(Dispatchers.IO) {
            if (!connect()) throw IllegalStateException("daemon down")
            cmd("spoof $ip 00:00:00:00:00:00", 300000)
        }
    }

    suspend fun stopSpoof() {
        withContext(Dispatchers.IO) {
            runCatching { cmd("stop", 5000) }
        }
    }

    suspend fun restore(ip: String, mac: String) {
        withContext(Dispatchers.IO) {
            if (!connect()) throw IllegalStateException("daemon down")
            cmd("restore $ip $mac", 10000)
        }
    }

    fun close() {
        runCatching { sock?.close() }
        sock = null
    }
}