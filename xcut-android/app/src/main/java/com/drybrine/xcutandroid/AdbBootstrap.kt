package com.drybrine.xcutandroid

import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.os.Build
import com.drybrine.xcutandroid.crypto.AdbCrypto
import com.drybrine.xcutandroid.crypto.Ed25519Ops
import com.drybrine.xcutandroid.crypto.Spake2
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.io.File
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.charset.StandardCharsets
import java.security.KeyPair
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.security.interfaces.RSAPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlin.coroutines.resume

/**
 * Built-in "Shizuku replacement": wireless-debugging pairing + adb-over-TLS
 * connection + shell execution, all from inside the app. No root, no third
 * party app. Android 11+ (API 30+) required.
 */
class AdbBootstrap(context: Context) {

    private val appContext = context.applicationContext
    private val keyFile = File(appContext.filesDir, "adbkey.pkcs8")
    private val pubFile = File(appContext.filesDir, "adbkey.pub")

    data class Discovered(val name: String, val host: String, val port: Int)

    /** Discover wireless-debugging services. Returns pairing + connect endpoints. */
    suspend fun discover(): Pair<List<Discovered>, List<Discovered>> =
        withContext(Dispatchers.IO) {
            val nsd = appContext.getSystemService(Context.NSD_SERVICE) as NsdManager
            val pairing = discoverType(nsd, "_adb-tls-pairing._tcp.")
            val connect = discoverType(nsd, "_adb-tls-connect._tcp.")
            pairing to connect
        }

    private suspend fun discoverType(nsd: NsdManager, type: String): List<Discovered> =
        suspendCancellableCoroutine { cont ->
            var results = mutableListOf<Discovered>()
            var done = false
            val listener = object : NsdManager.DiscoveryListener {
                override fun onDiscoveryStarted(serviceType: String) {}
                override fun onServiceFound(serviceInfo: NsdServiceInfo) {
                    val outer = this
                    nsd.resolveService(serviceInfo, object : NsdManager.ResolveListener {
                        override fun onResolveFailed(serviceInfo: NsdServiceInfo, errorCode: Int) {}
                        override fun onServiceResolved(info: NsdServiceInfo) {
                            val host = info.host ?: return
                            results.add(Discovered(info.serviceName, host.hostAddress ?: "", info.port))
                            nsd.stopServiceDiscovery(outer)
                            if (!done) {
                                done = true
                                cont.resume(results)
                            }
                        }
                    })
                }

                override fun onServiceLost(serviceInfo: NsdServiceInfo) {}
                override fun onDiscoveryStopped(serviceType: String) {}
                override fun onStartDiscoveryFailed(serviceType: String, errorCode: Int) {
                    if (!done) { done = true; cont.resume(results) }
                }

                override fun onStopDiscoveryFailed(serviceType: String, errorCode: Int) {}
            }
            nsd.discoverServices(type, NsdManager.PROTOCOL_DNS_SD, listener)
            cont.invokeOnCancellation { nsd.stopServiceDiscovery(listener) }
        }

    // ---------------- key management ----------------

    fun loadOrCreateKey(): KeyPair {
        if (keyFile.exists()) {
            val priv = AdbCrypto.pkcs8Private(keyFile.readBytes())
            return KeyPair(AdbCrypto.x509Public(pubFile.readBytes()), priv)
        }
        val kp = AdbCrypto.generateRsaKey()
        keyFile.writeBytes((kp.private as java.security.interfaces.RSAPrivateKey).encoded)
        pubFile.writeBytes(AdbCrypto.userKeyLine(kp.public as RSAPublicKey).toByteArray())
        return kp
    }

    val userKeyLine: String
        get() = String(pubFile.readBytes(), StandardCharsets.UTF_8)

    // ---------------- pairing ----------------

    private fun trustAllContext(kp: KeyPair): SSLContext {
        val cert: X509Certificate = AdbCrypto.selfSignedCert(kp)
        val kmf = javax.net.ssl.KeyManagerFactory.getInstance("X509")
        val ks = java.security.KeyStore.getInstance("PKCS12")
        ks.load(null, null)
        ks.setKeyEntry("adb", kp.private, null, arrayOf(cert))
        kmf.init(ks, null)
        val trustAll = arrayOf<TrustManager>(object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
            override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
        })
        return SSLContext.getInstance("TLS").apply {
            init(kmf.keyManagers, trustAll, java.security.SecureRandom())
        }
    }

    /** TLS 1.3 exporter ("adb-label\0", 64 bytes) via Conscrypt. */
    private fun exportKeyingMaterial(sslSocket: SSLSocket, length: Int): ByteArray {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            // com.android.org.conscrypt.Conscrypt is @SystemApi; HiddenApiBypass
            // lifts the exemption gate (same approach as Kadb/ADBeesh)
            org.lsposed.hiddenapibypass.HiddenApiBypass.addHiddenApiExemptions(
                "Lcom/android/org/conscrypt/Conscrypt;"
            )
            val cls = Class.forName("com.android.org.conscrypt.Conscrypt")
            cls.getMethod(
                "exportKeyingMaterial",
                SSLSocket::class.java,
                String::class.java,
                ByteArray::class.java,
                Int::class.javaPrimitiveType,
            ).invoke(null, sslSocket, "adb-label\u0000", null, length) as ByteArray
        } else {
            val cls = Class.forName("org.conscrypt.Conscrypt")
            cls.getMethod(
                "exportKeyingMaterial",
                SSLSocket::class.java,
                String::class.java,
                ByteArray::class.java,
                Int::class.javaPrimitiveType,
            ).invoke(null, sslSocket, "adb-label\u0000", null, length) as ByteArray
        }
    }

    /**
     * Run the wireless-debugging pairing protocol. `code` is the 6-digit code
     * shown on the phone. On success the device stores our RSA key.
     */
    suspend fun pair(host: String, port: Int, code: String) {
        val kp = loadOrCreateKey()
        withContext(Dispatchers.IO) {
            val ssl = trustAllContext(kp)
            val sock = ssl.socketFactory.createSocket() as SSLSocket
            sock.connect(InetSocketAddress(host, port), 10000)
            sock.soTimeout = 10000
            sock.use {
                val inS = DataInputStream(it.getInputStream())
                val outS = DataOutputStream(it.getOutputStream())

                // password = code + TLS exported key material ("adb-label", 64 bytes)
                val exported = exportKeyingMaterial(it, 64)
                val password = code.toByteArray() + exported

                val alice = Spake2.newContext(Spake2.Role.ALICE,
                    Spake2.CLIENT_NAME, Spake2.SERVER_NAME)
                val myMsg = Spake2.generateMsg(alice, password)

                // send SPAKE2_MSG
                writePairingPacket(outS, 2 /*SPAKE2_MSG*/, myMsg)
                // read peer SPAKE2_MSG
                val their = readPairingPacket(inS, 2)
                val keyMaterial = Spake2.processMsg(alice, their) ?: throw IllegalStateException("spake2 failed")
                val cipherKey = AdbCrypto.hkdf(keyMaterial, null,
                    AdbCrypto.HKDF_INFO_PAIRING.toByteArray(), 16)

                // send encrypted PeerInfo: type=ADB_RSA_PUB_KEY(0) + key line bytes
                val lineBytes = userKeyLine.toByteArray()
                val peerInfo = ByteArray(8192)
                peerInfo[0] = 0
                System.arraycopy(lineBytes, 0, peerInfo, 1, lineBytes.size)
                val enc = AdbCrypto.gcmEncrypt(cipherKey, 0, peerInfo)
                writePairingPacket(outS, 3 /*PEER_INFO*/, enc)

                // read peer PeerInfo (device GUID) - verify decrypt
                val theirEnc = readPairingPacket(inS, 3)
                AdbCrypto.gcmDecrypt(cipherKey, 0, theirEnc)
            }
        }
    }

    private fun writePairingPacket(out: DataOutputStream, type: Int, payload: ByteArray) {
        out.writeByte(1) // version
        out.writeByte(type)
        out.writeInt(payload.size)
        out.write(payload)
        out.flush()
    }

    private fun readPairingPacket(input: DataInputStream, expectedType: Int): ByteArray {
        val version = input.readUnsignedByte()
        val type = input.readUnsignedByte()
        val size = input.readInt()
        if (version < 1 || size <= 0 || size > 16384) throw IllegalStateException("bad pairing packet v=$version")
        val payload = ByteArray(size)
        input.readFully(payload)
        if (type != expectedType) throw IllegalStateException("unexpected pairing type $type")
        return payload
    }

    // ---------------- connect + shell ----------------

    /** Connect over TLS, authenticate, and run one shell command to completion. */
    suspend fun shellExec(host: String, port: Int, command: String): Pair<Int, String> =
        withContext(Dispatchers.IO) {
            val kp = loadOrCreateKey()
            val ssl = trustAllContext(kp)
            val sock = ssl.socketFactory.createSocket() as SSLSocket
            sock.connect(InetSocketAddress(host, port), 10000)
            sock.soTimeout = 15000
            sock.use {
                val input = DataInputStream(it.getInputStream())
                val output = DataOutputStream(it.getOutputStream())
                adbAuth(input, output, kp)
                val out = StringBuilder()
                val exit = adbShell(input, output, command, out)
                exit to out.toString()
            }
        }

    private fun adbAuth(input: DataInputStream, output: DataOutputStream, kp: KeyPair) {
        // CNXN host:: 
        val payload = "host::\u0000".toByteArray()
        val cnxn = byteArrayOf(
            'C'.code.toByte(), 'N'.code.toByte(), 'X'.code.toByte(), 'N'.code.toByte())
        writeAdbPacket(output, cnxn, 0x01000001, 4096, payload)
        var authed = false
        var tries = 0
        while (!authed && tries < 3) {
            tries++
            val msg = readAdbPacket(input)
            val cmd = String(msg.command, StandardCharsets.US_ASCII)
            when (cmd) {
                "AUTH" -> {
                    when (msg.arg0) {
                        1 -> { // TOKEN: respond signature + public key
                            val token = msg.payload
                            val sig = AdbCrypto.rsaSha1Sign(kp.private, token)
                            writeAdbPacket(output, "AUTH".toByteArray(), 2, 0, sig)
                            val pubLine = (userKeyLine + "\u0000").toByteArray()
                            writeAdbPacket(output, "AUTH".toByteArray(), 3, 0, pubLine)
                        }
                        2 -> { /* signature accepted? wait for CNXN */ }
                    }
                }
                "CNXN" -> {
                    authed = true
                }
            }
        }
        if (!authed) throw IllegalStateException("adb auth failed")
    }

    /** Classic shell,v2: service. Returns exit code via shell protocol packets. */
    private fun adbShell(input: DataInputStream, output: DataOutputStream, command: String, out: StringBuilder): Int {
        val dest = "shell,v2:$command\u0000".toByteArray()
        writeAdbPacket(output, "OPEN".toByteArray(), 1, 0, dest)
        var exit = 0
        while (true) {
            val msg = readAdbPacket(input)
            when (String(msg.command, StandardCharsets.US_ASCII)) {
                "WRTE" -> {
                    var pos = 0
                    val data = msg.payload
                    while (pos + 8 <= data.size) {
                        val id = data[pos].toInt() and 0xff
                        val length = leInt(data.copyOfRange(pos + 4, pos + 8))
                        if (pos + 8 + length > data.size) break
                        val chunk = data.copyOfRange(pos + 8, pos + 8 + length)
                        when (id) {
                            1 -> out.append(String(chunk, StandardCharsets.UTF_8))
                            2 -> out.append(String(chunk, StandardCharsets.UTF_8))
                            3 -> exit = chunk.getOrNull(0)?.toInt()?.and(0xff) ?: exit
                        }
                        pos += 8 + length
                    }
                    writeAdbPacket(output, "OKAY".toByteArray(), 1, 0, ByteArray(0))
                }
                "CLSE", "OKAY" -> return exit
                else -> throw IllegalStateException("unexpected adb packet ${String(msg.command)}")
            }
        }
    }

    private fun writeAdbPacket(output: DataOutputStream, command: ByteArray, arg0: Int, arg1: Int, payload: ByteArray) {
        val cmd = leInt(command)
        output.writeInt(cmd)
        output.writeInt(arg0)
        output.writeInt(arg1)
        output.writeInt(payload.size)
        output.writeInt(0) // data_check skipped (protocol >= A_VERSION_SKIP_CHECKSUM)
        output.writeInt(cmd xor -1) // magic = command ^ 0xffffffff
        output.write(payload)
        output.flush()
    }

    private fun leInt(b: ByteArray): Int =
        (b[0].toInt() and 0xff) or ((b[1].toInt() and 0xff) shl 8) or
                ((b[2].toInt() and 0xff) shl 16) or ((b[3].toInt() and 0xff) shl 24)

    private class AdbMsg(val command: ByteArray, val arg0: Int, val arg1: Int, val payload: ByteArray)

    private fun readAdbPacket(input: DataInputStream): AdbMsg {
        val header = ByteArray(24)
        input.readFully(header)
        val command = header.copyOfRange(0, 4)
        val arg0 = leInt(header.copyOfRange(4, 8))
        val arg1 = leInt(header.copyOfRange(8, 12))
        val dataLength = leInt(header.copyOfRange(12, 16))
        if (dataLength < 0 || dataLength > 65536) throw EOFException("bad adb length $dataLength")
        val payload = ByteArray(dataLength)
        input.readFully(payload)
        return AdbMsg(command, arg0, arg1, payload)
    }

    /** One-shot convenience: pair if needed then push+start the xcut daemon binary. */
    suspend fun startDaemon(host: String, port: Int, binaryB64: String) {
        val push = "echo $binaryB64 | base64 -d > /data/local/tmp/xcutd && chmod 755 /data/local/tmp/xcutd && echo PUSHED"
        val (exit1, out1) = shellExec(host, port, push)
        if (exit1 != 0 || !out1.contains("PUSHED")) throw IllegalStateException("push failed: $exit1 $out1")
        val start = "setsid /data/local/tmp/xcutd --daemon </dev/null >/dev/null 2>&1 & echo STARTED"
        val (exit2, out2) = shellExec(host, port, start)
        if (!out2.contains("STARTED")) throw IllegalStateException("start failed: $exit2 $out2")
    }
}