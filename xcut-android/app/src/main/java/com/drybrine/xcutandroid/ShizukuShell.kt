package com.drybrine.xcutandroid

import kotlin.concurrent.thread
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import rikka.shizuku.Shizuku

data class ShellResult(val exit: Int, val stdout: String, val stderr: String)

object ShizukuShell {

    /** Run a shell command as the Shizuku server uid (ADB shell, uid 2000). */
    suspend fun run(command: String): ShellResult = withContext(Dispatchers.IO) {
        if (!Shizuku.pingBinder()) {
            return@withContext ShellResult(-1, "", "shizuku binder dead / not started")
        }
        val out = StringBuilder()
        val err = StringBuilder()
        val exit = try {
            val process = Shizuku.newProcess(arrayOf("/system/bin/sh", "-c", command), null, null)
            val tOut = thread { out.append(process.inputStream.bufferedReader().use { it.readText() }) }
            val tErr = thread { err.append(process.errorStream.bufferedReader().use { it.readText() }) }
            val code = process.waitFor()
            tOut.join()
            tErr.join()
            code
        } catch (e: Exception) {
            err.append(e.toString())
            -1
        }
        ShellResult(exit, out.toString(), err.toString())
    }

    /** Report what the shell uid can actually do: uid + capability bits. */
    suspend fun capabilities(): Map<String, String> {
        val r = run("id -u; grep -E '^CapEff|^Uid' /proc/self/status")
        val map = mutableMapOf(
            "uid" to "?",
            "cap_eff" to "0",
            "CAP_NET_RAW" to "?",
            "CAP_NET_ADMIN" to "?",
        )
        for (line in r.stdout.lines()) {
            val t = line.trim()
            when {
                t.matches(Regex("\\d+")) -> map["uid"] = t
                t.startsWith("CapEff") -> {
                    val hex = t.substringAfter('\t').trim()
                    map["cap_eff"] = hex
                    val bits = hex.toLongOrNull(16) ?: 0L
                    map["CAP_NET_RAW"] = ((bits shr 13) and 1L == 1L).toString()
                    map["CAP_NET_ADMIN"] = ((bits shr 12) and 1L == 1L).toString()
                }
            }
        }
        return map
    }
}
