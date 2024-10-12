###################
#Feature extractor#
###################
'''
This function extracts features from an Android APK file using the Androguard library. 
The class is designed to run in a separate thread to avoid blocking the main application.

The run method extracts features from the APK file, including:
    API Call Signature: Specific details about method calls in an app.
    Manifest Permission: Permissions declared in the manifest file to access restricted features.
    Intent: A messaging object for inter-component communication.
    Commands Signature: Method signatures for custom command invocations (not a standard term).

The class emits progress signals (0-100%) to update the application's progress bar. The class
also reorders the df to prepare it for predictions.
'''

from PyQt5.QtCore import pyqtSignal, QObject, QThread
import pandas as pd
from PyQt5.QtWidgets import QApplication
from androguard.misc import AnalyzeAPK


class FeatureExtractionWorker(QObject):
    progress = pyqtSignal(int)  # Signal to emit progress
    finished = pyqtSignal(pd.DataFrame)  # Signal to emit when extraction is complete
    error = pyqtSignal(str)  # Signal to emit if there's an error

    def __init__(self, apk_file):
        super().__init__()
        self.apk_file = apk_file

    
    def run(self):
        try:
            # Categorized list of features
            features = {
                'API call signature': ['transact', 'onServiceConnected', 'bindService', 'attachInterface', 
                    'ServiceConnection', 'android.os.Binder', 'Ljava.lang.Class.getCanonicalName', 
                    'Ljava.lang.Class.getMethods', 'Ljava.lang.Class.cast', 'Ljava.net.URLDecoder', 
                    'android.content.pm.Signature', 'android.telephony.SmsManager', 'getBinder', 'ClassLoader', 
                    'Landroid.content.Context.registerReceiver', 'Ljava.lang.Class.getField', 'Landroid.content.Context.unregisterReceiver', 
                    'Ljava.lang.Class.getDeclaredField', 'getCallingUid', 'Ljavax.crypto.spec.SecretKeySpec', 'android.content.pm.PackageInfo', 
                    'KeySpec', 'TelephonyManager.getLine1Number', 'DexClassLoader', 'HttpGet.init', 'SecretKey', 'Ljava.lang.Class.getMethod', 
                    'System.loadLibrary', 'android.intent.action.SEND', 'Ljavax.crypto.Cipher', 'android.telephony.gsm.SmsManager', 
                    'TelephonyManager.getSubscriberId', 'Runtime.getRuntime', 'Ljava.lang.Object.getClass', 'Ljava.lang.Class.forName', 'Binder', 
                    'IBinder', 'android.os.IBinder', 'createSubprocess', 'URLClassLoader', 'abortBroadcast', 'TelephonyManager.getDeviceId', 'getCallingPid',
                    'Ljava.lang.Class.getPackage', 'Ljava.lang.Class.getDeclaredClasses', 'PathClassLoader', 'TelephonyManager.getSimSerialNumber', 
                    'Runtime.load', 'TelephonyManager.getCallState', 'TelephonyManager.getSimCountryIso', 'sendMultipartTextMessage', 'PackageInstaller', 
                    'sendDataMessage', 'HttpPost.init', 'Ljava.lang.Class.getClasses', 'TelephonyManager.isNetworkRoaming', 'HttpUriRequest', 'divideMessage', 
                    'Runtime.exec', 'TelephonyManager.getNetworkOperator', 'MessengerService', 'IRemoteService', 'SET_ALARM', 'ACCOUNT_MANAGER',
                    'TelephonyManager.getSimOperator', 'onBind', 'Process.start', 'Context.bindService', 'ProcessBuilder', 'Ljava.lang.Class.getResource', 
                    'defineClass', 'findClass', 'Runtime.loadLibrary'],

                'Manifest Permission': ['SEND_SMS', 'READ_PHONE_STATE', 'GET_ACCOUNTS', 'RECEIVE_SMS', 'READ_SMS', 'USE_CREDENTIALS', 'MANAGE_ACCOUNTS', 
                    'WRITE_SMS', 'READ_SYNC_SETTINGS', 'AUTHENTICATE_ACCOUNTS', 'WRITE_HISTORY_BOOKMARKS', 'INSTALL_PACKAGES', 'CAMERA', 'WRITE_SYNC_SETTINGS',
                    'READ_HISTORY_BOOKMARKS', 'INTERNET', 'RECORD_AUDIO', 'NFC', 'ACCESS_LOCATION_EXTRA_COMMANDS', 'WRITE_APN_SETTINGS', 'BIND_REMOTEVIEWS', 
                    'READ_PROFILE', 'MODIFY_AUDIO_SETTINGS', 'READ_SYNC_STATS', 'BROADCAST_STICKY', 'WAKE_LOCK', 'RECEIVE_BOOT_COMPLETED', 'RESTART_PACKAGES', 
                    'BLUETOOTH', 'READ_CALENDAR', 'READ_CALL_LOG', 'SUBSCRIBED_FEEDS_WRITE', 'READ_EXTERNAL_STORAGE', 'VIBRATE', 'ACCESS_NETWORK_STATE', 
                    'SUBSCRIBED_FEEDS_READ', 'CHANGE_WIFI_MULTICAST_STATE', 'WRITE_CALENDAR', 'MASTER_CLEAR', 'UPDATE_DEVICE_STATS', 'WRITE_CALL_LOG', 
                    'DELETE_PACKAGES', 'GET_TASKS', 'GLOBAL_SEARCH', 'DELETE_CACHE_FILES', 'WRITE_USER_DICTIONARY', 'REORDER_TASKS', 'WRITE_PROFILE', 
                    'SET_WALLPAPER', 'BIND_INPUT_METHOD', 'READ_SOCIAL_STREAM', 'READ_USER_DICTIONARY', 'PROCESS_OUTGOING_CALLS', 'CALL_PRIVILEGED', 
                    'BIND_WALLPAPER', 'RECEIVE_WAP_PUSH', 'DUMP', 'BATTERY_STATS', 'ACCESS_COARSE_LOCATION', 'SET_TIME', 'WRITE_SOCIAL_STREAM', 
                    'WRITE_SETTINGS', 'REBOOT', 'BLUETOOTH_ADMIN', 'BIND_DEVICE_ADMIN', 'WRITE_GSERVICES', 'KILL_BACKGROUND_PROCESSES', 'STATUS_BAR', 
                    'PERSISTENT_ACTIVITY', 'CHANGE_NETWORK_STATE', 'RECEIVE_MMS', 'SET_TIME_ZONE', 'CONTROL_LOCATION_UPDATES', 'BROADCAST_WAP_PUSH', 
                    'BIND_ACCESSIBILITY_SERVICE', 'ADD_VOICEMAIL', 'CALL_PHONE', 'BIND_APPWIDGET', 'FLASHLIGHT', 'READ_LOGS', 'SET_PROCESS_LIMIT', 
                    'MOUNT_UNMOUNT_FILESYSTEMS', 'BIND_TEXT_SERVICE', 'INSTALL_LOCATION_PROVIDER', 'SYSTEM_ALERT_WINDOW', 'MOUNT_FORMAT_FILESYSTEMS', 
                    'CHANGE_CONFIGURATION', 'CLEAR_APP_USER_DATA', 'CHANGE_WIFI_STATE', 'READ_FRAME_BUFFER', 'ACCESS_SURFACE_FLINGER', 'BROADCAST_SMS', 
                    'EXPAND_STATUS_BAR', 'INTERNAL_SYSTEM_WINDOW', 'SET_ACTIVITY_WATCHER', 'WRITE_CONTACTS', 'BIND_VPN_SERVICE', 'DISABLE_KEYGUARD', 
                    'ACCESS_MOCK_LOCATION', 'GET_PACKAGE_SIZE', 'MODIFY_PHONE_STATE', 'CHANGE_COMPONENT_ENABLED_STATE', 'CLEAR_APP_CACHE', 'SET_ORIENTATION', 
                    'READ_CONTACTS', 'DEVICE_POWER', 'HARDWARE_TEST', 'ACCESS_WIFI_STATE', 'WRITE_EXTERNAL_STORAGE', 'ACCESS_FINE_LOCATION', 'SET_WALLPAPER_HINTS', 
                    'SET_PREFERRED_APPLICATIONS', 'WRITE_SECURE_SETTINGS'],

                'Intent': ['android.intent.action.BOOT_COMPLETED', 'android.intent.action.PACKAGE_REPLACED', 'android.intent.action.SEND_MULTIPLE', 'android.intent.action.TIME_SET',
                    'android.intent.action.PACKAGE_REMOVED', 'android.intent.action.TIMEZONE_CHANGED', 'android.intent.action.ACTION_POWER_DISCONNECTED', 'android.intent.action.PACKAGE_ADDED', 
                    'android.intent.action.ACTION_SHUTDOWN', 'android.intent.action.PACKAGE_DATA_CLEARED', 'android.intent.action.PACKAGE_CHANGED', 'android.intent.action.NEW_OUTGOING_CALL', 
                    'android.intent.action.SENDTO', 'android.intent.action.CALL', 'android.intent.action.SCREEN_ON', 'android.intent.action.BATTERY_OKAY', 'android.intent.action.PACKAGE_RESTARTED', 
                    'android.intent.action.CALL_BUTTON', 'android.intent.action.SCREEN_OFF', 'intent.action.RUN', 'android.intent.action.SET_WALLPAPER', 'android.intent.action.BATTERY_LOW', 
                    'android.intent.action.ACTION_POWER_CONNECTED'],

                'Commands signature': ['mount', 'chmod', 'remount', 'chown', '/system/bin', '/system/app']
            }
            
            # Initialize dictionary to track feature presence for each category
            feature_presence = {category: {feature: 0 for feature in features[category]} for category in features}

            # Analyze the APK
            '''
                Loading the APK: It loads the APK file and extracts its contents, including the manifest 
                and classes.Decoding DEX Files: It decodes the DEX (Dalvik Executable) files inside the APK, 
                converting them into a format that can be analyzed. This process includes converting bytecode 
                into a more readable form (often using Smali or Java-like representations).
                    
                    apk: This object contains the APK metadata and allows you to access the permissions and other high-level details.
                    dvm: This object represents the Dalvik Virtual Machine, which allows for more in-depth analysis of the DEX bytecode.
                    dx: This is where you can access the decoded methods, classes, and other components from the APK's DEX files.
            '''

            apk, _, dx = AnalyzeAPK(self.apk_file)

            # Extract permissions and methods from the APK
            permissions = apk.get_permissions()
            methods = dx.get_methods()

            # Check for feature presence in 'Manifest Permission'
            for feature in features['Manifest Permission']:
                self.progress.emit(25)
                QApplication.processEvents()
                if feature in permissions:
                    feature_presence['Manifest Permission'][feature] = 1

            # Check for feature presence in 'API call signature' and 'Commands signature'
            for method in methods:
                self.progress.emit(50)
                QApplication.processEvents()
                method_str = str(method)
                for category in ['API call signature', 'Commands signature']:
                    for feature in features[category]:
                        if feature in method_str:
                            feature_presence[category][feature] = 1

            # Check for feature presence in 'Intent'
            for feature in features['Intent']:
                self.progress.emit(75)
                QApplication.processEvents()
                if feature in permissions or feature in str(methods):
                    feature_presence['Intent'][feature] = 1

            # Convert the feature presence dictionary to a DataFrame
            flat_features = {f"{feature}": presence 
                             for feature_dict in feature_presence.values() 
                             for feature, presence in feature_dict.items()}
            unordered_df = pd.DataFrame([flat_features])
            
            #Reorder the columns of the new dataframe so that the feature names are in 
            #the same order they were in fit 
            df_used_for_fit = pd.read_csv('models/static/trained model/static_training_df.csv')
            df = unordered_df.reindex(columns=df_used_for_fit.columns)
            df.to_csv('gui/feature_presence_results.csv',index=False)
            
            # Set progress to 100%
            self.progress.emit(100)  
            self.finished.emit(df)

        except Exception as e:
            self.error.emit(str(e))
