package org.beiwe.app.ui.utils;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.graphics.BitmapFactory;
import android.graphics.Color;
import android.os.Build;
import android.util.Log;

import androidx.core.app.NotificationCompat;

import org.beiwe.app.JSONUtils;
import org.beiwe.app.R;
import org.beiwe.app.storage.PersistentData;
import org.beiwe.app.storage.TextFileManager;
import org.beiwe.app.survey.AudioRecorderActivity;
import org.beiwe.app.survey.AudioRecorderEnhancedActivity;
import org.beiwe.app.survey.SurveyActivity;
import org.beiwe.app.ui.NotificationsKt;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.List;

import static org.beiwe.app.UtilsKt.printe;

/**The purpose of this class is to deal with all that has to do with Survey Notifications.
 * This is a STATIC method, and is called from the main service.
 * @author Eli Jones */
//TODO: Low priority: Eli. Redoc.1
public class SurveyNotifications {
	private static final String CHANNEL_ID = "survey_notification_channel";

	/**Show notifications for each survey in surveyIds, as long as that survey exists in PersistentData. */
	public static void showSurveyNotifications(Context appContext, List<String> surveyIds) {
		if (surveyIds != null) {
			List<String> idsOfStoredSurveys = JSONUtils.jsonArrayToStringList(PersistentData.getSurveyIdsJsonArray());
			for (String surveyId : surveyIds) {
				if (idsOfStoredSurveys.contains(surveyId)) {
					displaySurveyNotification(appContext, surveyId);
				} else {
					String errorMsg = "Tried to show notification for survey ID " + surveyId +
							" but didn't have that survey stored in PersistentData.";
					printe(errorMsg);
					TextFileManager.writeDebugLogStatement(errorMsg);
				}
			}
		}
	}

	/**Creates a survey notification that transfers the user to the survey activity.
	 * Note: the notification can only be dismissed through submitting the survey
	 * @param appContext */
	public static void displaySurveyNotification(Context appContext, String surveyId) {
		if (PersistentData.getSurveyType(surveyId).equals("tracking_survey")) {
			NotificationsKt.showSurveyNotification(appContext, surveyId);
		} else if (PersistentData.getSurveyType(surveyId).equals("audio_survey")) {
			NotificationsKt.showVoiceRecordingNotification(appContext, surveyId);
		} else {
			TextFileManager.getDebugLogFile().writeEncrypted(System.currentTimeMillis()+" "+" encountered unknown survey type: " + PersistentData.getSurveyType(surveyId)+", cannot schedule survey.");
		}
	}


	/**Use to dismiss the notification corresponding the surveyIdInt.
	 * @param appContext
	 * @param surveyId */
	public static void dismissNotification(Context appContext, String surveyId) {
 		NotificationManager notificationManager = (NotificationManager) appContext.getSystemService(Context.NOTIFICATION_SERVICE);
		notificationManager.cancel(surveyId.hashCode());
		PersistentData.setSurveyNotificationState(surveyId, false);
	}
	
	
	/**Tries to determine the type of audio survey.  If it is an Enhanced audio survey AudioRecorderEnhancedActivity.class is returned,
	 * any other outcome (including an inability to determine type) returns AudioRecorderActivity.class instead. */
	@SuppressWarnings("rawtypes")
	public static Class getAudioSurveyClass (String surveyId) {
		JSONObject surveySettings;
		try {
			surveySettings = new JSONObject(PersistentData.getSurveySettings(surveyId));
			if (surveySettings.getString("audio_survey_type").equals("raw"))
				return AudioRecorderEnhancedActivity.class;
		} catch (JSONException e) {
			e.printStackTrace();
		}
		return AudioRecorderActivity.class;
	}
}