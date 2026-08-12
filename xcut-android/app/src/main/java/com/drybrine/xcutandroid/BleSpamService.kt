package com.drybrine.xcutandroid

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.os.IBinder

class BleSpamService : Service() {

    private var spammer: BleSpammer? = null

    override fun onCreate() {
        super.onCreate()
        val channel = NotificationChannel(
            "ble-spam", "BLE Spam", NotificationManager.IMPORTANCE_LOW
        )
        getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val typeName = intent?.getStringExtra(EXTRA_TYPE)
        if (typeName == null || typeName == ACTION_STOP) {
            stopSpam()
            return START_NOT_STICKY
        }
        val type = runCatching { SpamType.valueOf(typeName) }.getOrNull()
        if (type == null) {
            stopSpam()
            return START_NOT_STICKY
        }
        spammer?.stop()
        spammer = BleSpammer(this).also { it.start(type) }
        val notification: Notification = Notification.Builder(this, "ble-spam")
            .setContentTitle("xcut BLE spam")
            .setContentText("${type.label} aktif - tap untuk berhenti")
            .setSmallIcon(android.R.drawable.ic_media_play)
            .setOngoing(true)
            .build()
        startForeground(1, notification)
        return START_STICKY
    }

    private fun stopSpam() {
        spammer?.stop()
        spammer = null
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onDestroy() {
        spammer?.stop()
        spammer = null
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    companion object {
        const val EXTRA_TYPE = "type"
        const val ACTION_STOP = "stop"
    }
}