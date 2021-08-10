package org.beiwe.app.ui

import android.app.Activity
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.graphics.BitmapFactory
import android.os.Build
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import org.beiwe.app.R
import org.beiwe.app.session.SessionActivity
import org.beiwe.app.survey.SurveyActivity
import org.beiwe.app.ui.utils.SurveyNotifications


val MESSAGES_CHANNEL_ID = "messages_notification_channel"
val SURVEYS_CHANNEL_ID = "survey_notification_channel"


fun showMessageNotification(appContext: Context, messageContent: String) {
//    createNotificationChannel(appContext, "Messages", "Messages from the research staff")
//    createAndShowNotification(appContext, "New message", messageContent, R.drawable.message_icon)
}

// TODO: only the last notification stays; the other one seems to get overwritten
fun showSurveyNotification(appContext: Context, surveyId: String) {
    Log.d("JoshLog", "showSurveyNotification()")
    createNotificationChannel(appContext, SURVEYS_CHANNEL_ID,"Survey Notifications", "Surveys and voice recording prompts")
    createAndShowNotification(
        appContext,
        SurveyActivity::class.java,
        appContext.getString(R.string.new_android_survey_notification_title),
        appContext.getString(R.string.new_android_survey_notification_details),
        R.drawable.survey_icon_large,
        appContext.getString(R.string.start_tracking_survey),
        surveyId
    )
}


fun showVoiceRecordingNotification(appContext: Context, surveyId: String) {
    Log.d("JoshLog", "showVoiceRecordingNotification()")
    createNotificationChannel(appContext, SURVEYS_CHANNEL_ID,"Survey Notifications", "Surveys and voice recording prompts")
    createAndShowNotification(
        appContext,
        SurveyNotifications.getAudioSurveyClass(surveyId),
        appContext.getString(R.string.new_audio_survey_notification_title),
        appContext.getString(R.string.new_audio_survey_notification_details),
        R.drawable.voice_recording_icon_large,
        appContext.getString(R.string.start_audio_survey),
        surveyId
    )
}


private fun createAndShowNotification(
    appContext: Context,
    destinationActivity: Class<*>,
    title: String,
    content: String,
    iconId: Int,
    intentAction: String,
    surveyId: String
) {
    // Create Intent
    var activityIntent = Intent(appContext, destinationActivity)
    activityIntent.action = intentAction  // TODO: is this necessary?
    activityIntent.putExtra("surveyId", surveyId)
    activityIntent.flags = Intent.FLAG_ACTIVITY_CLEAR_TOP //modifies behavior when the user is already in the app
    val pendingActivityIntent = PendingIntent.getActivity(
        appContext,
        surveyId.hashCode(),
        activityIntent,
        PendingIntent.FLAG_CANCEL_CURRENT
    )
    // Create NotificationBuilder
    var notificationBuilder = NotificationCompat.Builder(appContext, MESSAGES_CHANNEL_ID)
        .setContentIntent(pendingActivityIntent)
        .setContentText(content)
        .setContentTitle(title)
        .setGroup(surveyId) // This prevents them from replacing the previous notifications
        .setLargeIcon(BitmapFactory.decodeResource(appContext.resources, iconId))
        .setOngoing(true)  // Prevent the notification from being swiped away
        .setPriority(NotificationCompat.PRIORITY_DEFAULT)
        .setShowWhen(true)  // Show the timestamp on the notification
        .setSmallIcon(R.mipmap.ic_launcher)
    // Show notification
    with(NotificationManagerCompat.from(appContext)) {
        notify(42, notificationBuilder.build())  // TODO: what should the notificationId int be?
    }
}


private fun createNotificationChannel(appContext: Context, channelId: String, channelName: String, descriptionText: String) {
    // TODO: make Channel an enum https://stackoverflow.com/a/53160059
    val notificationManager =
        appContext.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
    if (notificationManager == null) {
        return
    } else if (notificationManager.getNotificationChannel(channelId) != null) {
        return
    }

    // Only necessary on API 26+ (Android O: that's "Oh", not "Zero")
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
        val importance = NotificationManager.IMPORTANCE_LOW
        val channel = NotificationChannel(channelId, channelName, importance).apply {
            description = descriptionText
        }
        // Register the channel with the OS
        val notificationManager: NotificationManager =
            appContext.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        notificationManager.createNotificationChannel(channel)

        // TODO: decide whether to keep these settings from the old Java code
//        channel.enableLights(true)
//        channel.setLightColor(Color.RED)
//        channel.setVibrationPattern(longArrayOf(0, 1000, 500, 1000))
//        channel.enableVibration(true)
    }
}

// TODO: disable badge for persistent data collection notification
// TODO: https://developer.android.com/training/notify-user/channels
