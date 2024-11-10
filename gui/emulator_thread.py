from PyQt5.QtCore import QThread, pyqtSignal, QTimer
import subprocess
import time

class EmulatorThread(QThread):
    emulator_started = pyqtSignal()  # Signal when emulator is started
    emulator_ready = pyqtSignal()  # Signal when emulator is ready
    adb_check = pyqtSignal(str)  # Signal to emit ADB connection status
    error = pyqtSignal(str)  # Signal for error handling
    apk_installed = pyqtSignal()  # Signal when APK is installed
    feature_extraction_started = pyqtSignal()  # Signal to start feature extraction
    log_signal = pyqtSignal(str)  # Signal to send log messages to the main UI

    def __init__(self, emulator_dir, emulator_command, adb_command, apk_file):
        super().__init__()
        self.emulator_dir = emulator_dir
        self.emulator_command = emulator_command
        self.adb_command = adb_command
        self.apk_file = apk_file

    def run(self):
        try:
            # Start emulator
            self.start_emulator()

            # Check emulator status
            self.check_emulator_ready()

            # Install APK
            self.install_apk(self.apk_file)

            # Trigger feature extraction once APK is installed
            self.feature_extraction_started.emit()

        except Exception as e:
            self.error.emit(str(e))


    def log(self, message):
        """Emit a log message to be captured by the GUI."""
        self.log_signal.emit(message)

    def start_emulator(self):
        """Start the emulator."""
        self.log("Starting emulator...")
        try:
            self.process = subprocess.Popen(self.emulator_command, shell=True, cwd=self.emulator_dir)
            self.emulator_started.emit()
        except Exception as e:
            self.error.emit(f"Error starting emulator: {e}")

    def check_emulator_ready(self):
        """Check if the emulator is ready using ADB."""
        self.log("Checking if emulator is ready...")
        time.sleep(65)  # adb connection delay
        try:
            if self.process.poll() is None:  # Check if process is still running
                result = subprocess.run(self.adb_command, capture_output=True, text=True)
                if "device" in result.stdout:
                    self.emulator_ready.emit()
                else:
                    self.log("Emulator not ready. Retrying...")
                    time.sleep(5)
                    self.check_emulator_ready()
            else:
                self.log("Emulator process has stopped.")
                self.error.emit("Emulator process has stopped.")
        except Exception as e:
            print(f"Error checking emulator status: {e}")
            #self.log(f"Error checking emulator status: {e}")
            #self.error.emit(f"Error checking emulator status: {e}")
            

    def install_apk(self, apk_file):
        """Install the APK on the emulator."""
        self.log(f"Installing APK: {apk_file}")
        try:
            install_command = ["adb", "install", apk_file]
            result = subprocess.run(install_command, capture_output=True, text=True)
            if result.returncode == 0:
                self.apk_installed.emit()
            else:
                self.log(f"Failed to install APK: {result.stderr}\nRetrying install.")
                time.sleep(15)
                self.install_apk(apk_file)
        except Exception as e:
                self.log(f"Failed to install APK: {result.stderr}\nRetrying install.")
                time.sleep(15)
                self.install_apk(apk_file)

