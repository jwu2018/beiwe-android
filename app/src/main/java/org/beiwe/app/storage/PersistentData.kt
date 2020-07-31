package org.beiwe.app.storage

import android.annotation.SuppressLint
import android.content.Context
import android.content.SharedPreferences
import android.content.SharedPreferences.Editor
import org.beiwe.app.BuildConfig
import org.beiwe.app.JSONUtils
import org.beiwe.app.R
import org.json.JSONArray
import org.json.JSONException
import java.security.SecureRandom
import java.util.*

/**A class for managing patient login sessions.
 * Uses SharedPreferences in order to save username-password combinations.
 * @author Dor Samet, Eli Jones, Josh Zagorsky */
object PersistentData {
    var NULL_ID = "NULLID"

    private const val MAX_LONG = 9223372036854775807L
    private const val PRIVATE_MODE = 0
    private var isInitialized = false

    // Private things that are encapsulated using functions in this class
    private lateinit var pref: SharedPreferences
    private lateinit var editor: Editor
    private lateinit var appContext: Context

    /**  Editor key-strings  */
    private const val PREF_NAME = "BeiwePref"
    private const val SERVER_URL_KEY = "serverUrl"
    private const val KEY_ID = "uid"
    private const val KEY_PASSWORD = "password"
    private const val IS_REGISTERED = "IsRegistered"
    private const val DEVICE_SETTINGS_SET = "deviceSettingsSet"
    private const val KEY_WRITTEN = "keyWritten"
    private const val ERROR_DURING_REGISTRATION = "errorDuringRegistration"
    private const val LOGIN_EXPIRATION = "loginExpirationTimestamp"
    private const val PCP_PHONE_KEY = "primary_care"
    private const val PASSWORD_RESET_NUMBER_KEY = "reset_number"
    private const val FCM_INSTANCE_ID = "fcmInstanceID"
    private const val ACCELEROMETER = "accelerometer"
    private const val GYROSCOPE = "gyroscope"
    private const val GPS = "gps"
    private const val CALLS = "calls"
    private const val TEXTS = "texts"
    private const val WIFI = "wifi"
    private const val BLUETOOTH = "bluetooth"
    private const val POWER_STATE = "power_state"
    private const val ALLOW_UPLOAD_OVER_CELLULAR_DATA = "allow_upload_over_cellular_data"
    private const val ACCELEROMETER_OFF_DURATION_SECONDS = "accelerometer_off_duration_seconds"
    private const val ACCELEROMETER_ON_DURATION_SECONDS = "accelerometer_on_duration_seconds"
    private const val GYROSCOPE_ON_DURATION_SECONDS = "gyro_on_duration_seconds"
    private const val GYROSCOPE_OFF_DURATION_SECONDS = "gyro_off_duration_seconds"
    private const val BLUETOOTH_ON_DURATION_SECONDS = "bluetooth_on_duration_seconds"
    private const val BLUETOOTH_TOTAL_DURATION_SECONDS = "bluetooth_total_duration_seconds"
    private const val BLUETOOTH_GLOBAL_OFFSET_SECONDS = "bluetooth_global_offset_seconds"
    private const val CHECK_FOR_NEW_SURVEYS_FREQUENCY_SECONDS = "check_for_new_surveys_frequency_seconds"
    private const val CREATE_NEW_DATA_FILES_FREQUENCY_SECONDS = "create_new_data_files_frequency_seconds"
    private const val GPS_OFF_DURATION_SECONDS = "gps_off_duration_seconds"
    private const val GPS_ON_DURATION_SECONDS = "gps_on_duration_seconds"
    private const val SECONDS_BEFORE_AUTO_LOGOUT = "seconds_before_auto_logout"
    private const val UPLOAD_DATA_FILES_FREQUENCY_SECONDS = "upload_data_files_frequency_seconds"
    private const val VOICE_RECORDING_MAX_TIME_LENGTH_SECONDS = "voice_recording_max_time_length_seconds"
    private const val WIFI_LOG_FREQUENCY_SECONDS = "wifi_log_frequency_seconds"
    private const val SURVEY_IDS = "survey_ids"
    //	private static final String SURVEY_QUESTION_IDS = "question_ids";
    /*#################################################################################################
	################################### Initializing and Editing ######################################
	#################################################################################################*/
    /**The publicly accessible initializing function for the LoginManager, initializes the internal variables.  */
    @SuppressLint("ApplySharedPref")
    @JvmStatic
    fun initialize(context: Context) {
        if (isInitialized)
            return

        appContext = context
        pref = appContext.getSharedPreferences(PREF_NAME, PRIVATE_MODE) //sets Shared Preferences private mode
        editor = pref.edit()
        editor.commit()
        isInitialized = true
    }

    private fun putCommit(name: String, l: Long) {
        editor.putLong(name, l)
        editor.commit()
    }

    private fun putCommit(name: String, b: Boolean) {
        editor.putBoolean(name, b)
        editor.commit()
    }

    private fun putCommit(name: String, s: String) {
        editor.putString(name, s)
        editor.commit()
    }

    private fun putCommit(name: String, f: Float) {
        editor.putFloat(name, f)
        editor.commit()
    }

    private fun putCommit(name: String, i: Int) {
        editor.putInt(name, i)
        editor.commit()
    }

    /*#####################################################################################
	##################################### User State ######################################
	#####################################################################################*/// If the current time is earlier than the expiration time, return TRUE; else FALSE
    /** Quick check for login.  */
    val isLoggedIn: Boolean
        // If the current time is earlier than the expiration time, return TRUE; else FALSE
        get() = System.currentTimeMillis() < pref.getLong(LOGIN_EXPIRATION, 0)

    /** Set the login session to expire a fixed amount of time in the future  */
    @JvmStatic
    fun loginOrRefreshLogin() = putCommit(LOGIN_EXPIRATION, System.currentTimeMillis() + millisecondsBeforeAutoLogout)

    /** Set the login session to "expired"  */
    @JvmStatic
    fun logout() = putCommit(LOGIN_EXPIRATION, 0)

    @JvmStatic
    var isRegistered: Boolean
        get() = pref.getBoolean(IS_REGISTERED, false)
        set(value) = putCommit(IS_REGISTERED, value)

    @JvmStatic
    var deviceSettingsAreSet: Boolean
        get() = pref.getBoolean(DEVICE_SETTINGS_SET, false)
        set(value) = putCommit(DEVICE_SETTINGS_SET, value)

    @JvmStatic
    var keyWritten: Boolean
        get() = pref.getBoolean(KEY_WRITTEN, false)
        set(value) = putCommit(KEY_WRITTEN, value)

    @JvmStatic
    var errorDuringRegistration: Boolean
        get() = pref.getBoolean(ERROR_DURING_REGISTRATION, false)
        set(value) = putCommit(ERROR_DURING_REGISTRATION, value)

    /*######################################################################################
	##################################### Passwords ########################################
	######################################################################################*/
    /**Checks that an input matches valid password requirements. (this only checks length)
     * Throws up an alert notifying the user if the password is not valid.
     * @param password
     * @return true or false based on password requirements. */
    @JvmStatic
    fun passwordMeetsRequirements(password: String): Boolean = minPasswordLength() <= password.length

    @JvmStatic
    fun minPasswordLength(): Int {
        return if (BuildConfig.APP_IS_BETA) 1 else 6
    }

    /**Takes an input string and returns a boolean value stating whether the input matches the current password.  */
    @JvmStatic
    fun checkPassword(input: String?): Boolean = password == EncryptionEngine.safeHash(input)

    /**Sets a password to a hash of the provided value.  */
    @JvmStatic
    fun setThePassword(password: String?) = putCommit(KEY_PASSWORD, EncryptionEngine.safeHash(password))

    /*#####################################################################################
	################################# Firebase Cloud Messaging Instance ID ################
	#####################################################################################*/
    @JvmStatic
    var fCMInstanceID: String
        get() = pref.getString(FCM_INSTANCE_ID, null)
        set(fcmInstanceID) = putCommit(FCM_INSTANCE_ID, fcmInstanceID)

    /*#####################################################################################
	################################# Listener Settings ###################################
	#####################################################################################*/
    @JvmStatic
    var accelerometerEnabled: Boolean
        get() = pref.getBoolean(ACCELEROMETER, false)
        set(enabled) = putCommit(ACCELEROMETER, enabled)

    @JvmStatic
    var gyroscopeEnabled: Boolean
        get() = pref.getBoolean(GYROSCOPE, false)
        set(enabled) = putCommit(GYROSCOPE, enabled)

    @JvmStatic
    var gpsEnabled: Boolean
        get() = pref.getBoolean(GPS, false)
        set(enabled) = putCommit(GPS, enabled)

    @JvmStatic
    var callsEnabled: Boolean
        get() = pref.getBoolean(CALLS, false)
        set(enabled) = putCommit(CALLS, enabled)

    @JvmStatic
    var textsEnabled: Boolean
        get() = pref.getBoolean(TEXTS, false)
        set(enabled) = putCommit(TEXTS, enabled)

    @JvmStatic
    var wifiEnabled: Boolean
        get() = pref.getBoolean(WIFI, false)
        set(enabled) = putCommit(WIFI, enabled)

    @JvmStatic
    var bluetoothEnabled: Boolean
        get() = pref.getBoolean(BLUETOOTH, false)
        set(enabled) = putCommit(BLUETOOTH, enabled)

    @JvmStatic
    var powerStateEnabled: Boolean
        get() = pref.getBoolean(POWER_STATE, false)
        set(enabled) = putCommit(POWER_STATE, enabled)

    @JvmStatic
    var allowUploadOverCellularData: Boolean
        get() = pref.getBoolean(ALLOW_UPLOAD_OVER_CELLULAR_DATA, false)
        set(enabled) = putCommit(ALLOW_UPLOAD_OVER_CELLULAR_DATA, enabled)

    /*#####################################################################################
	################################## Timer Settings #####################################
	#####################################################################################*/
    // Default timings (only used if app doesn't download custom timings)
    private const val DEFAULT_ACCELEROMETER_OFF_MINIMUM_DURATION: Long = 10
    private const val DEFAULT_ACCELEROMETER_ON_DURATION = 10 * 60.toLong()
    private const val DEFAULT_GYROSCOPE_OFF_MINIMUM_DURATION: Long = 10
    private const val DEFAULT_GYROSCOPE_ON_DURATION = 10 * 60.toLong()
    private const val DEFAULT_BLUETOOTH_ON_DURATION = 1 * 60.toLong()
    private const val DEFAULT_BLUETOOTH_TOTAL_DURATION = 5 * 60.toLong()
    private const val DEFAULT_BLUETOOTH_GLOBAL_OFFSET = 0 * 60.toLong()
    private const val DEFAULT_CHECK_FOR_NEW_SURVEYS_PERIOD = 24 * 60 * 60.toLong()
    private const val DEFAULT_CREATE_NEW_DATA_FILES_PERIOD = 15 * 60.toLong()
    private const val DEFAULT_GPS_OFF_MINIMUM_DURATION = 5 * 60.toLong()
    private const val DEFAULT_GPS_ON_DURATION = 5 * 60.toLong()
    private const val DEFAULT_SECONDS_BEFORE_AUTO_LOGOUT = 5 * 60.toLong()
    private const val DEFAULT_UPLOAD_DATA_FILES_PERIOD: Long = 60
    private const val DEFAULT_VOICE_RECORDING_MAX_TIME_LENGTH = 4 * 60.toLong()
    private const val DEFAULT_WIFI_LOG_FREQUENCY = 5 * 60.toLong()

    @JvmStatic
    var gyroscopeOffDurationMilliseconds: Long
        get() = 1000L * pref.getLong(GYROSCOPE_OFF_DURATION_SECONDS, DEFAULT_GYROSCOPE_OFF_MINIMUM_DURATION)
        set(seconds: Long) = putCommit(GYROSCOPE_OFF_DURATION_SECONDS, seconds)

    @JvmStatic
    var gyroscopeOnDurationMilliseconds: Long
        get() = 1000L * pref.getLong(GYROSCOPE_ON_DURATION_SECONDS, DEFAULT_GYROSCOPE_ON_DURATION)
        set(seconds: Long) = putCommit(GYROSCOPE_ON_DURATION_SECONDS, seconds)

    @JvmStatic
    var accelerometerOffDurationMilliseconds: Long
        get() = 1000L * pref.getLong(ACCELEROMETER_OFF_DURATION_SECONDS, DEFAULT_ACCELEROMETER_OFF_MINIMUM_DURATION)
        set(seconds: Long) = putCommit(ACCELEROMETER_OFF_DURATION_SECONDS, seconds)

    @JvmStatic
    var accelerometerOnDurationMilliseconds: Long
        get() = 1000L * pref.getLong(ACCELEROMETER_ON_DURATION_SECONDS, DEFAULT_ACCELEROMETER_ON_DURATION)
        set(seconds: Long) = putCommit(ACCELEROMETER_ON_DURATION_SECONDS, seconds)

    @JvmStatic
    var bluetoothOnDurationMilliseconds: Long
        get() = 1000L * pref.getLong(BLUETOOTH_ON_DURATION_SECONDS, DEFAULT_BLUETOOTH_ON_DURATION)
        set(seconds: Long) = putCommit(BLUETOOTH_ON_DURATION_SECONDS, seconds)

    @JvmStatic
    var bluetoothTotalDurationMilliseconds: Long
        get() = 1000L * pref.getLong(BLUETOOTH_TOTAL_DURATION_SECONDS, DEFAULT_BLUETOOTH_TOTAL_DURATION)
        set(seconds: Long) = putCommit(BLUETOOTH_TOTAL_DURATION_SECONDS, seconds)

    @JvmStatic
    var bluetoothGlobalOffsetMilliseconds: Long
        get() = 1000L * pref.getLong(BLUETOOTH_GLOBAL_OFFSET_SECONDS, DEFAULT_BLUETOOTH_GLOBAL_OFFSET)
        set(seconds: Long) = putCommit(BLUETOOTH_GLOBAL_OFFSET_SECONDS, seconds)

    @JvmStatic
    var checkForNewSurveysFrequencyMilliseconds: Long
        get() = 1000L * pref.getLong(CHECK_FOR_NEW_SURVEYS_FREQUENCY_SECONDS, DEFAULT_CHECK_FOR_NEW_SURVEYS_PERIOD)
        set(seconds: Long) = putCommit(CHECK_FOR_NEW_SURVEYS_FREQUENCY_SECONDS, seconds)

    @JvmStatic
    var createNewDataFilesFrequencyMilliseconds: Long
        get() = 1000L * pref.getLong(CREATE_NEW_DATA_FILES_FREQUENCY_SECONDS, DEFAULT_CREATE_NEW_DATA_FILES_PERIOD)
        set(seconds: Long) = putCommit(CREATE_NEW_DATA_FILES_FREQUENCY_SECONDS, seconds)

    @JvmStatic
    var gpsOffDurationMilliseconds: Long
        get() = 1000L * pref.getLong(GPS_OFF_DURATION_SECONDS, DEFAULT_GPS_OFF_MINIMUM_DURATION)
        set(seconds: Long) = putCommit(GPS_OFF_DURATION_SECONDS, seconds)

    @JvmStatic
    var gpsOnDurationMilliseconds: Long
        get() = 1000L * pref.getLong(GPS_ON_DURATION_SECONDS, DEFAULT_GPS_ON_DURATION)
        set(seconds: Long) = putCommit(GPS_ON_DURATION_SECONDS, seconds)

    @JvmStatic
    var millisecondsBeforeAutoLogout: Long
        get() = 1000L * pref.getLong(SECONDS_BEFORE_AUTO_LOGOUT, DEFAULT_SECONDS_BEFORE_AUTO_LOGOUT)
        set(seconds: Long) = putCommit(SECONDS_BEFORE_AUTO_LOGOUT, seconds)

    @JvmStatic
    var uploadDataFilesFrequencyMilliseconds: Long
        get() = 1000L * pref.getLong(UPLOAD_DATA_FILES_FREQUENCY_SECONDS, DEFAULT_UPLOAD_DATA_FILES_PERIOD)
        set(seconds: Long) = putCommit(UPLOAD_DATA_FILES_FREQUENCY_SECONDS, seconds)

    @JvmStatic
    var voiceRecordingMaxTimeLengthMilliseconds: Long
        get() = 1000L * pref.getLong(VOICE_RECORDING_MAX_TIME_LENGTH_SECONDS, DEFAULT_VOICE_RECORDING_MAX_TIME_LENGTH)
        set(seconds: Long) = putCommit(VOICE_RECORDING_MAX_TIME_LENGTH_SECONDS, seconds)

    @JvmStatic
    var wifiLogFrequencyMilliseconds: Long
        get() = 1000L * pref.getLong(WIFI_LOG_FREQUENCY_SECONDS, DEFAULT_WIFI_LOG_FREQUENCY)
        set(seconds: Long) = putCommit(WIFI_LOG_FREQUENCY_SECONDS, seconds)

//    @JvmStatic
//    fun setAccelerometerOffDurationSeconds(seconds: Long) {
//        putCommit(ACCELEROMETER_OFF_DURATION_SECONDS, seconds)
//    }
//
//    @JvmStatic
//    fun setAccelerometerOnDurationSeconds(seconds: Long) {
//        putCommit(ACCELEROMETER_ON_DURATION_SECONDS, seconds)
//    }
//
//    @JvmStatic
//    fun setGyroscopeOffDurationSeconds(seconds: Long) {
//        putCommit(GYROSCOPE_OFF_DURATION_SECONDS, seconds)
//    }
//
//    @JvmStatic
//    fun setGyroscopeOnDurationSeconds(seconds: Long) {
//        putCommit(GYROSCOPE_ON_DURATION_SECONDS, seconds)
//    }
//
//    @JvmStatic
//    fun setBluetoothOnDurationSeconds(seconds: Long) {
//        putCommit(BLUETOOTH_ON_DURATION_SECONDS, seconds)
//    }
//
//    @JvmStatic
//    fun setBluetoothTotalDurationSeconds(seconds: Long) {
//        putCommit(BLUETOOTH_TOTAL_DURATION_SECONDS, seconds)
//    }
//
//    @JvmStatic
//    fun setBluetoothGlobalOffsetSeconds(seconds: Long) {
//        putCommit(BLUETOOTH_GLOBAL_OFFSET_SECONDS, seconds)
//    }
//
//    @JvmStatic
//    fun setCheckForNewSurveysFrequencySeconds(seconds: Long) {
//        putCommit(CHECK_FOR_NEW_SURVEYS_FREQUENCY_SECONDS, seconds)
//    }
//
//    @JvmStatic
//    fun setCreateNewDataFilesFrequencySeconds(seconds: Long) {
//        putCommit(CREATE_NEW_DATA_FILES_FREQUENCY_SECONDS, seconds)
//    }
//
//    @JvmStatic
//    fun setGpsOffDurationSeconds(seconds: Long) {
//        putCommit(GPS_OFF_DURATION_SECONDS, seconds)
//    }
//
//    @JvmStatic
//    fun setGpsOnDurationSeconds(seconds: Long) {
//        putCommit(GPS_ON_DURATION_SECONDS, seconds)
//    }
//
//    @JvmStatic
//    fun setSecondsBeforeAutoLogout(seconds: Long) {
//        putCommit(SECONDS_BEFORE_AUTO_LOGOUT, seconds)
//    }
//
//    @JvmStatic
//    fun setUploadDataFilesFrequencySeconds(seconds: Long) {
//        putCommit(UPLOAD_DATA_FILES_FREQUENCY_SECONDS, seconds)
//    }
//
//    @JvmStatic
//    fun setVoiceRecordingMaxTimeLengthSeconds(seconds: Long) {
//        putCommit(VOICE_RECORDING_MAX_TIME_LENGTH_SECONDS, seconds)
//    }
//
//    @JvmStatic
//    fun setWifiLogFrequencySeconds(seconds: Long) {
//        putCommit(WIFI_LOG_FREQUENCY_SECONDS, seconds)
//    }
//
//    //accelerometer, gyroscope bluetooth, new surveys, create data files, gps, logout,upload, wifilog (not voice recording, that doesn't apply
//    @JvmStatic
//    fun setMostRecentAlarmTime(identifier: String, time: Long) {
//        putCommit("$identifier-prior_alarm", time)
//    }

    @JvmStatic
    fun getMostRecentAlarmTime(identifier: String): Long = pref.getLong("$identifier-prior_alarm", 0)

    //we want default to be 0 so that checks "is this value less than the current expected value" (eg "did this timer event pass already")
    /*###########################################################################################
	################################### Text Strings ############################################
	###########################################################################################*/
    private const val ABOUT_PAGE_TEXT_KEY = "about_page_text"
    private const val CALL_CLINICIAN_BUTTON_TEXT_KEY = "call_clinician_button_text"
    private const val CONSENT_FORM_TEXT_KEY = "consent_form_text"
    private const val SURVEY_SUBMIT_SUCCESS_TOAST_TEXT_KEY = "survey_submit_success_toast_text"

    @JvmStatic
    var aboutPageText: String
        get() {
            val defaultText = appContext!!.getString(R.string.default_about_page_text)
            return pref.getString(ABOUT_PAGE_TEXT_KEY, defaultText)!!
        }
        set(text) = putCommit(ABOUT_PAGE_TEXT_KEY, text)

    @JvmStatic
    var callClinicianButtonText: String
        get() {
            val defaultText = appContext!!.getString(R.string.default_call_clinician_text)!!
            return pref.getString(CALL_CLINICIAN_BUTTON_TEXT_KEY, defaultText)!!
        }
        set(text) = putCommit(CALL_CLINICIAN_BUTTON_TEXT_KEY, text)

    @JvmStatic
    var consentFormText: String
        get() {
            val defaultText = appContext!!.getString(R.string.default_consent_form_text)!!
            return pref.getString(CONSENT_FORM_TEXT_KEY, defaultText)!!
        }
        set(text) = putCommit(CONSENT_FORM_TEXT_KEY, text)

    @JvmStatic
    var surveySubmitSuccessToastText: String
        get() {
            val defaultText = appContext!!.getString(R.string.default_survey_submit_success_message)
            return pref.getString(SURVEY_SUBMIT_SUCCESS_TOAST_TEXT_KEY, defaultText)
        }
        set(text) = putCommit(SURVEY_SUBMIT_SUCCESS_TOAST_TEXT_KEY, text)

    private fun prependHttpsToServerUrl(serverUrl: String): String {
        return if (serverUrl.startsWith("https://"))
            serverUrl
        else if (serverUrl.startsWith("http://"))
            "https://" + serverUrl.substring(7, serverUrl.length)
        else
            "https://$serverUrl"
    }

    /*###########################################################################################
	################################### User Credentials ########################################
	###########################################################################################*/
    @JvmStatic
    var serverUrl: String
        get() = pref.getString(SERVER_URL_KEY, null)
        set(serverUrl) {
            putCommit(SERVER_URL_KEY, prependHttpsToServerUrl(serverUrl))
        }

    @JvmStatic
    fun setLoginCredentials(userID: String, password: String?) {
        putCommit(KEY_ID, userID)
        setThePassword(password)
    }

    @JvmStatic
    val password: String
        get() = pref.getString(KEY_PASSWORD, null)

    @JvmStatic
    val patientID: String
        get() = pref.getString(KEY_ID, NULL_ID)

    /*###########################################################################################
	#################################### Contact Numbers ########################################
	###########################################################################################*/
    @JvmStatic
    var primaryCareNumber: String
        get() = pref.getString(PCP_PHONE_KEY, "")
        set(phoneNumber) = putCommit(PCP_PHONE_KEY, phoneNumber)

    @JvmStatic
    var passwordResetNumber: String
        get() = pref.getString(PASSWORD_RESET_NUMBER_KEY, "")
        set(phoneNumber) = putCommit(PASSWORD_RESET_NUMBER_KEY, phoneNumber)

    /*###########################################################################################
	###################################### Survey Info ##########################################
	###########################################################################################*/
    @JvmStatic
    val surveyIds: List<String>
        get() = JSONUtils.jsonArrayToStringList(surveyIdsJsonArray)

    @JvmStatic
    fun getSurveyQuestionMemory(surveyId: String): MutableList<String?> {
        return JSONUtils.jsonArrayToStringList(getSurveyQuestionMemoryJsonArray(surveyId))
    }

    @JvmStatic
    fun getSurveyTimes(surveyId: String): String = pref.getString("$surveyId-times", null)

    @JvmStatic
    fun getSurveyContent(surveyId: String): String = pref.getString("$surveyId-content", null)

    @JvmStatic
    fun getSurveyType(surveyId: String): String = pref.getString("$surveyId-type", null)

    @JvmStatic
    fun getSurveySettings(surveyId: String): String = pref.getString("$surveyId-settings", null)

    @JvmStatic
    fun getSurveyNotificationState(surveyId: String): Boolean = pref.getBoolean("$surveyId-notificationState", false)

    @JvmStatic
    fun getMostRecentSurveyAlarmTime(surveyId: String): Long = pref.getLong("$surveyId-prior_alarm", MAX_LONG)

    @JvmStatic
    fun createSurveyData(surveyId: String, content: String, timings: String, type: String, settings: String) {
        setSurveyContent(surveyId, content)
        setSurveyTimes(surveyId, timings)
        setSurveyType(surveyId, type)
        setSurveySettings(surveyId, settings)
    }

    //individual setters
    @JvmStatic
    fun setSurveyContent(surveyId: String, content: String) = putCommit("$surveyId-content", content)

    @JvmStatic
    fun setSurveyTimes(surveyId: String, times: String) = putCommit("$surveyId-times", times)

    @JvmStatic
    fun setSurveyType(surveyId: String, type: String) = putCommit("$surveyId-type", type)

    @JvmStatic
    fun setSurveySettings(surveyId: String, settings: String) = putCommit("$surveyId-settings", settings)

    //survey state storage
    @JvmStatic
    fun setSurveyNotificationState(surveyId: String, bool: Boolean) {
        putCommit("$surveyId-notificationState", bool)
    }

    @JvmStatic
    fun setMostRecentSurveyAlarmTime(surveyId: String, time: Long) = putCommit("$surveyId-prior_alarm", time)

    @JvmStatic
    fun deleteSurvey(surveyId: String) {
        editor.remove("$surveyId-content")
        editor.remove("$surveyId-times")
        editor.remove("$surveyId-type")
        editor.remove("$surveyId-notificationState")
        editor.remove("$surveyId-settings")
        editor.remove("$surveyId-questionIds")
        editor.commit()
        removeSurveyId(surveyId)
    }// Log.d("persistant data", "getting ids: " + jsonString);
    //return empty if the list is empty

    //array style storage and removal for surveyIds and questionIds
    @JvmStatic
    val surveyIdsJsonArray: JSONArray
        get() {
            val jsonString = pref.getString(SURVEY_IDS, "0")
            // Log.d("persistant data", "getting ids: " + jsonString);
            return if (jsonString === "0") {
                JSONArray()
            } else try {
                JSONArray(jsonString)
            } catch (e: JSONException) {
                throw NullPointerException("getSurveyIds failed, json string was: $jsonString")
            } //return empty if the list is empty
        }

    @JvmStatic
    fun addSurveyId(surveyId: String) {
        val list = JSONUtils.jsonArrayToStringList(surveyIdsJsonArray)
        if (!list.contains(surveyId)) {
            list.add(surveyId)
            putCommit(SURVEY_IDS, JSONArray(list).toString())
        } else {
            throw NullPointerException("duplicate survey id added: $surveyId")
        } //we ensure uniqueness in the downloader, this should be unreachable.
    }

    private fun removeSurveyId(surveyId: String) {
        val list = JSONUtils.jsonArrayToStringList(surveyIdsJsonArray)
        if (list.contains(surveyId)) {
            list.remove(surveyId)
            putCommit(SURVEY_IDS, JSONArray(list).toString())
        } else {
            throw NullPointerException("survey id does not exist: $surveyId")
        } //we ensure uniqueness in the downloader, this should be unreachable.
    }

    private fun getSurveyQuestionMemoryJsonArray(surveyId: String): JSONArray {
        val jsonString = pref.getString("$surveyId-questionIds", "0")
        return if (jsonString === "0") {
            JSONArray()
        } else try {
            JSONArray(jsonString)
        } catch (e: JSONException) {
            throw NullPointerException("getSurveyIds failed, json string was: $jsonString")
        } //return empty if the list is empty
    }

    @JvmStatic
    fun addSurveyQuestionMemory(surveyId: String, questionId: String) {
        val list = getSurveyQuestionMemory(surveyId)
        // Log.d("persistent data", "adding questionId: " + questionId);
        if (!list.contains(questionId)) {
            list.add(questionId)
            putCommit("$surveyId-questionIds", JSONArray(list).toString())
        } else {
            throw NullPointerException("duplicate question id added: $questionId")
        } //we ensure uniqueness in the downloader, this should be unreachable.
    }

    @JvmStatic
    fun clearSurveyQuestionMemory(surveyId: String) {
        putCommit("$surveyId-questionIds", JSONArray().toString())
    }

    /*###########################################################################################
	###################################### Encryption ###########################################
	###########################################################################################*/
    private const val HASH_SALT_KEY = "hash_salt_key"
    private const val HASH_ITERATIONS_KEY = "hash_iterations_key"
    private const val USE_ANONYMIZED_HASHING_KEY = "use_anonymized_hashing"

    // Get salt for pbkdf2 hashing
    @JvmStatic
    val hashSalt: ByteArray
        get() {
            val saltString = pref.getString(HASH_SALT_KEY, null)

            return if (saltString == null) {
                // create salt if it does not exist
                val newSalt = SecureRandom.getSeed(64)
                putCommit(HASH_SALT_KEY, String(newSalt))
                newSalt
            } else
                saltString.toByteArray()
        }


    // Get iterations for pbkdf2 hashing
    @JvmStatic
    val hashIterations: Int
        get() {
            // create iterations if it does not exist
            val iterations = pref.getInt(HASH_ITERATIONS_KEY, 0)
            return if (iterations == 0) {
                // create random iteration count from 900 to 1100
                val newIterations = 1100 - Random().nextInt(200)
                putCommit(HASH_ITERATIONS_KEY, newIterations)
                newIterations
            } else
                iterations
        }

    //If not present, default to safe hashing
    @JvmStatic
    var useAnonymizedHashing: Boolean
        get() = pref.getBoolean(USE_ANONYMIZED_HASHING_KEY, true) //If not present, default to safe hashing
        set(useAnonymizedHashing) = putCommit(USE_ANONYMIZED_HASHING_KEY, useAnonymizedHashing)

    /*###########################################################################################
	###################################### FUZZY GPS ############################################
	###########################################################################################*/
    private const val USE_GPS_FUZZING_KEY = "gps_fuzzing_key"
    private const val LATITUDE_OFFSET_KEY = "latitude_offset_key"
    private const val LONGITUDE_OFFSET_KEY = "longitude_offset_key"// create random latitude offset between (-1, -.2) or (.2, 1)

    // create latitude offset if it does not exist
    @JvmStatic
    val latitudeOffset: Double
        get() {
            val latitudeOffset = pref.getFloat(LATITUDE_OFFSET_KEY, 0.0f)
            // create latitude offset if it does not exist
            return if (latitudeOffset == 0.0f && useGpsFuzzing) {
                // create random latitude offset between (-1, -.2) or (.2, 1)
                var newLatitudeOffset = (.2 + Math.random() * 1.6).toFloat()
                if (newLatitudeOffset > 1)
                    newLatitudeOffset = (newLatitudeOffset - .8f) * -1
                putCommit(LATITUDE_OFFSET_KEY, newLatitudeOffset)
                newLatitudeOffset.toDouble()
            } else
                latitudeOffset.toDouble()
        }// create random longitude offset between (-180, -10) or (10, 180)

    //create longitude offset if it does not exist
    @JvmStatic
    val longitudeOffset: Float
        get() {
            val longitudeOffset = pref.getFloat(LONGITUDE_OFFSET_KEY, 0.0f)
            //create longitude offset if it does not exist
            return if (longitudeOffset == 0.0f && useGpsFuzzing) {
                // create random longitude offset between (-180, -10) or (10, 180)
                var newLongitudeOffset = (10 + Math.random() * 340).toFloat()
                if (newLongitudeOffset > 180)
                    newLongitudeOffset = (newLongitudeOffset - 170) * -1
                putCommit(LONGITUDE_OFFSET_KEY, newLongitudeOffset)
                newLongitudeOffset
            } else
                longitudeOffset
        }

    @JvmStatic
    private var useGpsFuzzing: Boolean
        private get() = pref.getBoolean(USE_GPS_FUZZING_KEY, false)
        set(useFuzzyGps) = putCommit(USE_GPS_FUZZING_KEY, useFuzzyGps)

    /*###########################################################################################
	###################################### Call Buttons #########################################
	###########################################################################################*/
    private const val CALL_CLINICIAN_BUTTON_ENABLED_KEY = "call_clinician_button_enabled"
    private const val CALL_RESEARCH_ASSISTANT_BUTTON_ENABLED_KEY = "call_research_assistant_button_enabled"

    @JvmStatic
    var callClinicianButtonEnabled: Boolean
        get() = pref.getBoolean(CALL_CLINICIAN_BUTTON_ENABLED_KEY, false)
        set(enabled) = putCommit(CALL_CLINICIAN_BUTTON_ENABLED_KEY, enabled)

    @JvmStatic
    var callResearchAssistantButtonEnabled: Boolean
        get() = pref.getBoolean(CALL_RESEARCH_ASSISTANT_BUTTON_ENABLED_KEY, false)
        set(enabled) = putCommit(CALL_RESEARCH_ASSISTANT_BUTTON_ENABLED_KEY, enabled)

    /** if the key was not written, or the device settings failed to parse, or there was an error
     * in the registration request... return false.  */
    @JvmStatic
    fun checkBadRegistration(): Boolean {
//		Log.e("thang", "getKeyWritten: " + PersistentData.getKeyWritten() );
//		Log.e("thang", "getDeviceSettingsAreSet: " + PersistentData.getDeviceSettingsAreSet() );
//		Log.e("thang", "getErrorDuringRegistration: " + PersistentData.getErrorDuringRegistration() );
        return !keyWritten || !deviceSettingsAreSet || errorDuringRegistration
    }
}