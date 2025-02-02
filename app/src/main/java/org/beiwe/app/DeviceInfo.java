package org.beiwe.app;

import android.annotation.SuppressLint;
import android.bluetooth.BluetoothAdapter;
import android.content.Context;
import android.provider.Settings;

import org.beiwe.app.storage.EncryptionEngine;

/**This is a class that NEEDS to be instantiated in the main service. In order to get the Android ID, the class needs
 * Context. Once instantiated, the class assigns two variables for AndroidID and BluetoothMAC. Once they are instantiated,
 * they can be called from different classes to be used. They are hashed when they are called.
 * 
 * The class is used to grab unique ID data, and pass it to the server. The data is used while authenticating users
 * 
 * @author Dor Samet, Eli Jones */  

public class DeviceInfo {
	/* TODO:  Ensure this number is updated whenever a version of the app is pushed to the website for any reason.
	 * Don't forget to update the version in the android manifest, only the version string is visible to the user.
	 * Version history:
	 * 1: add additional device data during the registration process, including this version number.
	 * 2: added sms debugging
	 * 3: added universal crash log to the app
	 * 4: added a lot of CrashHandler integration to all sorts of error-handled conditions the codebase.
	 * 5: Initial version of Android 6.
	 * 		Enhanced Audio UI rewrite included,raw recording code is functional but not enabled, no standard on parsing audio surveys for their type.
	 * 6: second version of Android 6.
	 * 		Enhanced audio functionality is included and functional, fixed crash that came up on a device when the app was uninstalled and then reinstalled?
	 * 		A functionally identical 6 was later released, it contains a new error message for a new type of iOS-related registration error.
	 * 7: audio survey files now contain the surveyid for the correct audio survey.
	 * 8: Now support a flag for data upload over cellular, fixed bug in wifi scanning.
	 * 9: Moves Record/Play buttons outside the scroll window on voice recording screen.
	 * 10: app version 2.0, Change to TextFileManager to potentially improve uninitialized errors, added device idle and low power mode change to power state listener.
	 * 11: development version of 12.
	 * 12: app version 2.1, several bug fixes including a fix for the on-opening-surveyactivity crash and a crash that could occur when when encrypting audio files. Adds support for branching serveys (conditional display logic)
	 * 13: app version 2.1.1, data improvements to GPS and WIFI data streams, improvements in said data streams and additional context provided in the app log (debug log).
	 * 14: app version 2.1.2, minor behavior improvement in extremely rare occurrence inside of sessionActivity, see inline documentation there for details.
	 * 15: bug fix in crash handler
	 * 16: app version 2.1.3, rewrite of file uploading to fix App Not Responding (ANR) errors; also BackgroundService.onStartCommand() now uses START_REDELIVER_INTENT
	 * 17: app version 2.1.4, fixed a bug that still showed the next survey, even if that survey time had been deleted in the backend and the updatee had propagated to the phone
	 * 18: app version 2.1.5, fixed bugs with recording received SMS messages and sent MMS messages
	 * 19: app version 2.2.0, enabled app to point to any server URL; improved Registration and Password Reset interfaces and networking.
	 * 20: app version 2.2.1, updated text on Registration screens
	 * 21: app version 2.2.2, updates styles, restores persistent, individual survey notifications in Android 7
	 * 22: app version 2.2.3, improves error messages
	 * 23: app version 2.2.4, OnnelaLabServer version and GooglePlayStore version (with customizable URL) have different names (Beiwe vs. Beiwe2)
	 * 24: app version 2.2.5, handle null Bluetooth MAC Address in Android 8.0 and above
	 * 25: app version 2.2.6, fix crash on opening app from audio survey notification when AppContext is null
	 * 26: app version 2.2.7, Added Sentry
	 * 27: app version 2.3.0, fix restart on crash
	 * 28: app version 2.3.1, Add ACCESS_COARSE_LOCATION to permission handler
	 * 29: app version 2.3.2, Add more intents to wake up the app in the BootListener;
	 * 		fixed crashes in SMS Sent Listener, SpannableString survey questions, and Registration
	 * 		screen orientation change
	 * 30: app version 2.3.3, Adds a repeating timer to restart the Background Service if crashed,
	 * 		improves file upload, fixes an occasional crash in audio recordings,
	 * 		fixes an occasional crash in registration, handles image surveys without crashing
	 * 31: app version 2.4.0, Updates compile target to SDK 26 (Android 8.0),
	 *		implements anoynmized phone number and MAC address hashing,
	 *		prevents creation of header-less files when the phone is out of storage space,
	 *		fixes a crash in trying to upload files before registration
	 * 32: app version 2.4.1, Fixes survey notification crash on Android 4,
	 * 		prevent crash in phone call logger,
	 * 		protect against crash in MMS logger
	 * 33: app version 2.4.2, Fuzzes/anonymizes GPS data for studies on servers that enable it
	 * 34: app version 2.4.3, Removes "Call My Clinician" and "Call Research Assistant" button
	 *      for studies that have those set in App Settings. Defaults to showing the buttons.
	 * 35: app version 2.4.4, Allow Markdown URL links to be clickable
	 * 37: app version 2.5.0, googlePlayStore build variants no longer ask for SMS/MMS and Call Log
	 *      permissions because of Google policy changes effective March 9th, 2019.  onnelaLabServer
	 *      build variants still collect SMS/MMS and Call Log data.
	 * 38: app version 2.5.1, Adds gyroscope sensor. Sets minimum WiFi log frequency.
	 * 39: app version 2.6.0, Adds optional always-available surveys.
	 * 41: app version 2.6.1, Adds localization for Traditional Chinese (Taiwan)
	 * 42: app version 2.6.2, Deletes app data/registration for APK-installed (non-Google Play
	 *      Store-installed) app
	 * 43: app version 2.6.3, Fixes permissions request infinite loop in the onnelaLabServer build
	 *      variant
	 * 44: app version 3.0.0, Can receive survey push notifications. Upgrades compile SDK target to
	 *      Android 10. Blocks registration if doesn't download key and app settings.
	 * 45: app version 3.0.1, Improves Sentry error logging (includes study name and study id, if
	 *      available from the server), updates app logo, logs product flavor in identifiers.
	 * 46: app version 3.0.2, Reduces logging of ENOSPC out-of-storage-space errors, and adds a fix
	 *      for the sporadic invalid encryption key errors received on the backend.
	 * 47: app version 3.0.3, Updates Sentry DSN
	 * 48: app version 3.1.0, Adds foreground service, and optional ambient audio collection feature
	 *      (ambient audio can be enabled or disabled at the study level. It's disabled by default.)
	 * 49: app version 3.1.1, Fixes background location permission for Android 11 and above
	 * 50: app version 3.1.2, Only prompts for background location permission in onnelaLabServer and
	 *      commStatsCustomUrl versions; not in googlePlayStore version
	 * 51: app version 3.1.3, Silences the persistent data collection notification
	 * */

	private static String androidID;
	private static String bluetoothMAC;
	private static Context context;

	/** grab the Android ID and the Bluetooth's MAC address */
	@SuppressLint("HardwareIds")
	public static void initialize(Context appContext) {
		context = appContext;
		androidID = Settings.Secure.getString( appContext.getContentResolver(), Settings.Secure.ANDROID_ID ); // android ID appears to be a 64 bit string
		
		/* If the BluetoothAdapter is null, or if the BluetoothAdapter.getAddress() returns null,
		 * record an empty string for the Bluetooth MAC Address.
		 * The Bluetooth MAC Address is always empty in Android 8.0 and above, because the app needs
		 * the LOCAL_MAC_ADDRESS permission, which is a system permission that it's not allowed to
		 * have:
		 * https://android-developers.googleblog.com/2017/04/changes-to-device-identifiers-in.html
		 * The Bluetooth MAC Address is also sometimes empty on Android 7 and lower. */
		if ( android.os.Build.VERSION.SDK_INT >= 23) { //This will not work on all devices: http://stackoverflow.com/questions/33377982/get-bluetooth-local-mac-address-in-marshmallow
			String bluetoothAddress = Settings.Secure.getString(appContext.getContentResolver(), "bluetooth_address");
			if (bluetoothAddress == null) { bluetoothAddress = ""; }
			bluetoothMAC = EncryptionEngine.hashMAC(bluetoothAddress); }
		else { //Android before version 6
			BluetoothAdapter bluetoothAdapter = BluetoothAdapter.getDefaultAdapter();	
			if ( bluetoothAdapter == null || bluetoothAdapter.getAddress() == null ) { bluetoothMAC = ""; }
			else { bluetoothMAC = bluetoothAdapter.getAddress(); }
		}
	}
	
	public static String getBeiweVersion() {
		return BuildConfig.FLAVOR + "-" + BuildConfig.VERSION_NAME;
	}
	public static String getAndroidVersion() { return android.os.Build.VERSION.RELEASE; }
	public static String getProduct() { return android.os.Build.PRODUCT; }
	public static String getBrand() { return android.os.Build.BRAND; }
	public static String getHardwareId() { return android.os.Build.HARDWARE; }
	public static String getManufacturer() { return android.os.Build.MANUFACTURER; }
	public static String getModel() { return android.os.Build.MODEL; }
	public static String getAndroidID() { return EncryptionEngine.safeHash(androidID); }
	public static String getBluetoothMAC() { return EncryptionEngine.hashMAC(bluetoothMAC); }
}