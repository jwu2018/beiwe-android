package org.beiwe.app.ui

import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import org.beiwe.app.R


val MESSAGES_CHANNEL_ID = "messages_notification_channel"


fun displayMessageNotification(appContext: Context, messageContent: String) {
    createNotificationChannel(appContext)
    createAndDisplayMessageNotification(appContext, messageContent)
}


private fun createAndDisplayMessageNotification(appContext: Context, messageContent: String) {
    // TODO: move Channel IDs to constants file, if we really need multiple channels
    var notificationBuilder = NotificationCompat.Builder(appContext, MESSAGES_CHANNEL_ID)
        .setSmallIcon(R.mipmap.ic_launcher)
        .setContentTitle("New Message")  // TODO: move to strings.xml
        .setContentText(messageContent)  // TODO: change to a string
        .setPriority(NotificationCompat.PRIORITY_DEFAULT)

    with(NotificationManagerCompat.from(appContext)) {
        notify(42, notificationBuilder.build())  // TODO: what should the notificationId int be?
    }

}


private fun createNotificationChannel(appContext: Context) {
    // Only necessary on API 26+ (Android O: that's "Oh", not "Zero")
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
        val name = "Messages"
        val descriptionText = "Messages from the research staff"
        val importance = NotificationManager.IMPORTANCE_LOW
        val channel = NotificationChannel(MESSAGES_CHANNEL_ID, name, importance).apply {
            description = descriptionText
        }
        // Register the channel with the OS
        val notificationManager: NotificationManager =
            appContext.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        notificationManager.createNotificationChannel(channel)
    }
}

// TODO: disable badge for persistent data collection notification