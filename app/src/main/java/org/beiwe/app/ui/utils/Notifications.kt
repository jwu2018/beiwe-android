package org.beiwe.app.ui

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
import org.beiwe.app.JSONUtils
import org.beiwe.app.R
import org.beiwe.app.printe
import org.beiwe.app.storage.PersistentData
import org.beiwe.app.storage.TextFileManager
import org.beiwe.app.survey.AudioRecorderCommon
import org.beiwe.app.survey.SurveyActivity


val MESSAGES_CHANNEL_ID = "messages_notification_channel"
val SURVEYS_CHANNEL_ID = "survey_notification_channel"


fun showMessageNotification(appContext: Context, messageContent: String) {
//    createNotificationChannel(appContext, "Messages", "Messages from the research staff")
//    createAndShowNotification(appContext, "New message", messageContent, R.drawable.message_icon)
}


/**Show notifications for each survey in surveyIds, as long as that survey exists in PersistentData.  */
fun showAllSurveyNotifications(appContext: Context, surveyIds: List<String>?) {
    if (surveyIds != null) {
        val storedSurveyIds = JSONUtils.jsonArrayToStringList(PersistentData.getSurveyIdsJsonArray())
        for (surveyId in surveyIds) {
            if (storedSurveyIds.contains(surveyId)) {
                showSurveyNotification(appContext, surveyId)
            } else {
                val errorMsg = "Tried to show notification for survey ID " + surveyId +
                        " but didn't have that survey stored in PersistentData."
                printe(errorMsg)
                TextFileManager.writeDebugLogStatement(errorMsg)
            }
        }
    }
}


fun showSurveyNotification(appContext: Context, surveyId: String) {
    createNotificationChannel(appContext, SURVEYS_CHANNEL_ID,"Survey Notifications",
        "Surveys and voice recording prompts")
    val surveyType = PersistentData.getSurveyType(surveyId)
    if (surveyType == "tracking_survey") {
        createAndShowNotification(
            appContext,
            SURVEYS_CHANNEL_ID,
            SurveyActivity::class.java,
            appContext.getString(R.string.new_android_survey_notification_title),
            appContext.getString(R.string.new_android_survey_notification_details),
            R.drawable.survey_icon_large,
            appContext.getString(R.string.start_tracking_survey),
            surveyId
        )
    } else if (surveyType == "audio_survey") {
        createAndShowNotification(
            appContext,
            SURVEYS_CHANNEL_ID,
            AudioRecorderCommon.getAudioSurveyClass(surveyId),
            appContext.getString(R.string.new_audio_survey_notification_title),
            appContext.getString(R.string.new_audio_survey_notification_details),
            R.drawable.voice_recording_icon_large,
            appContext.getString(R.string.start_audio_survey),
            surveyId
        )
    } else {
        val msg = "encountered unknown survey type: " + surveyType + ", cannot schedule survey."
        TextFileManager.getDebugLogFile().writeEncrypted(msg)
    }
}


fun dismissNotification(appContext: Context, surveyId: String) {
    val notificationManager = NotificationManagerCompat.from(appContext)
    notificationManager.cancel(surveyId.hashCode())
    PersistentData.setSurveyNotificationState(surveyId, false)
}


private fun createAndShowNotification(
    appContext: Context,
    channelId: String,
    destinationActivity: Class<*>,
    title: String,
    content: String,
    iconId: Int,
    intentAction: String,
    surveyId: String
) {
    val surveyIdHash = surveyId.hashCode()
    // Create Intent (the Activity to open when the notification gets tapped on)
    var activityIntent = Intent(appContext, destinationActivity)
    activityIntent.action = intentAction  // TODO: is this necessary?
    activityIntent.putExtra("surveyId", surveyId)
    activityIntent.flags = Intent.FLAG_ACTIVITY_CLEAR_TOP //modifies behavior when the user is already in the app
    val pendingActivityIntent = PendingIntent.getActivity(
        appContext,
        surveyIdHash,
        activityIntent,
        PendingIntent.FLAG_CANCEL_CURRENT
    )
    // Create NotificationBuilder
    var notificationBuilder = NotificationCompat.Builder(appContext, channelId)
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
    val notificationManager = NotificationManagerCompat.from(appContext)
    /* Cancel the notification if it exists, then recreate it.  This is because FLAG_UPDATE_CURRENT
    *  didn't work on API 19. https://stackoverflow.com/a/21250686 */
    notificationManager.cancel(surveyIdHash)  // Cancel existing identical notification
    notificationManager.notify(surveyIdHash, notificationBuilder.build())
    // Save in PersistentData that the notification should be shown (in case the app restarts)
    PersistentData.setSurveyNotificationState(surveyId, true)
    // Check if notifications have been disabled, and log it if they are
    if (!notificationManager.areNotificationsEnabled()) {
        TextFileManager.getDebugLogFile().writeEncrypted(
            System.currentTimeMillis()
                .toString() + " " + "Participant has blocked notifications (1)"
        )
        Log.e("SurveyNotifications", "Participant has blocked notifications (1)")
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
    }
}

// TODO: disable badge for persistent data collection notification
// TODO: https://developer.android.com/training/notify-user/channels
