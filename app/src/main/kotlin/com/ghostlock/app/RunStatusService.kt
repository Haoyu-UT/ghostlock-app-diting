package com.ghostlock.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder

/**
 * Foreground service held for the duration of an attack.
 *
 * It exists for one reason: on OPLUS/ColorOS the vendor HANS freezer moves a
 * backgrounded app's whole uid into its frozen cgroup. The KSU manager's
 * late-load restart takes the foreground ~25 s into a GhostLock run, the
 * exploit app is demoted to cached, and ~11 s later the uid (app, native and
 * the root script) is frozen mid-handoff (measured 2026-11-10 on CPH2723:
 * app uid [18140, 19345, 18970] frozen at A+36 s, the run resumed only after
 * the app was raised again). A foreground service keeps the uid at
 * FOREGROUND_SERVICE importance, so the app can be behind the manager and keep
 * running.
 *
 * The notification doubles as the run-status surface. The result is posted as
 * a separate, dismissible notification when the run ends, so the user still has
 * a visible "it worked" marker after the service stops.
 */
class RunStatusService : Service() {
    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_START) {
            createChannel(this)
            val text = intent.getStringExtra(EXTRA_TEXT).orEmpty()
            startForegroundCompat(buildNotification(this, text, ongoing = true, success = false))
        } else {
            stopSelf()
            return START_NOT_STICKY
        }
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        /* stopService is the normal path (the ViewModel calls it when the run
         * ends); this only guarantees the FGS notification is gone even if the
         * process is torn down another way. */
        stopForeground(STOP_FOREGROUND_REMOVE)
        super.onDestroy()
    }

    private fun startForegroundCompat(notification: Notification) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    companion object {
        private const val CHANNEL_ID = "run_status"
        private const val NOTIFICATION_ID = 0x676c6f63 // "gloc"
        private const val RESULT_NOTIFICATION_ID = 0x676c6f64 // "glod"
        private const val ACTION_START = "com.ghostlock.app.action.RUN_STATUS_START"
        private const val EXTRA_TEXT = "text"
        private const val EXTRA_SUCCESS = "success"

        /** Start the foreground service; the caller runs on the UI path (tap). */
        fun start(context: Context, text: String) {
            val intent = Intent(context, RunStatusService::class.java)
                .setAction(ACTION_START)
                .putExtra(EXTRA_TEXT, text)
            runCatching { context.startForegroundService(intent) }
        }

        /**
         * Stop the service and post the run's result as a normal (dismissible)
         * notification. Called after the run completes, possibly while the app
         * is in the background — stopService and notify are both allowed there.
         */
        fun finish(context: Context, text: String, success: Boolean) {
            runCatching { context.stopService(Intent(context, RunStatusService::class.java)) }
            runCatching { postResult(context, text, success) }
        }

        private fun postResult(context: Context, text: String, success: Boolean) {
            if (text.isEmpty()) return
            createChannel(context)
            context.getSystemService(NotificationManager::class.java)
                .notify(RESULT_NOTIFICATION_ID, buildNotification(context, text, ongoing = false, success = success))
        }

        private fun createChannel(context: Context) {
            val manager = context.getSystemService(NotificationManager::class.java) ?: return
            if (manager.getNotificationChannel(CHANNEL_ID) != null) return
            val channel = NotificationChannel(
                CHANNEL_ID,
                context.getString(R.string.run_notif_channel_name),
                NotificationManager.IMPORTANCE_LOW,
            ).apply {
                description = context.getString(R.string.run_notif_channel_description)
                setShowBadge(false)
            }
            manager.createNotificationChannel(channel)
        }

        private fun buildNotification(
            context: Context,
            text: String,
            ongoing: Boolean,
            success: Boolean,
        ): Notification {
            val openApp = PendingIntent.getActivity(
                context,
                0,
                Intent(context, com.ghostlock.app.ui.MainActivity::class.java)
                    .addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
            )
            val title = context.getString(
                when {
                    ongoing -> R.string.run_notif_running_title
                    success -> R.string.run_notif_success_title
                    else -> R.string.run_notif_failure_title
                },
            )
            return Notification.Builder(context, CHANNEL_ID)
                /* A system drawable keeps the test line dependency-free; a
                 * product build should ship its own status icon. */
                .setSmallIcon(android.R.drawable.stat_notify_sync)
                .setContentTitle(title)
                .setContentText(text)
                .setStyle(Notification.BigTextStyle().bigText(text))
                .setOngoing(ongoing)
                .setAutoCancel(!ongoing)
                .setContentIntent(openApp)
                .setCategory(if (ongoing) Notification.CATEGORY_PROGRESS else Notification.CATEGORY_STATUS)
                .setVisibility(Notification.VISIBILITY_PRIVATE)
                .build()
        }
    }
}
