from PyQt5.QtCore import QThread, pyqtSignal, QTimer
import subprocess
import time
from androguard.misc import AnalyzeAPK

class EmulatorThread(QThread):
    emulator_started = pyqtSignal()  # Signal when emulator is started
    emulator_ready = pyqtSignal()  # Signal when emulator is ready
    adb_check = pyqtSignal(str)  # Signal to emit ADB connection status
    error = pyqtSignal(str)  # Signal for error handling
    apk_installed = pyqtSignal()  # Signal when APK is installed
    feature_extraction_started = pyqtSignal()  # Signal to start feature extraction
    monkey_test = pyqtSignal() # Signal when user interaction simulation is compelted
    log_signal = pyqtSignal(str)  # Signal to send log messages to the main UI
    

    def __init__(self, emulator_dir, emulator_command, adb_command, apk_file):
        super().__init__()
        self.emulator_dir = emulator_dir
        self.emulator_command = emulator_command
        self.adb_command = adb_command
        self.apk_file = apk_file
        self.installed  = False 
        
        
    def run(self):
        try:
            # Start emulator
            self.start_emulator()

            # Check emulator status
            self.check_emulator_ready()

            # Install APK only if emulator is running
            self.install_apk(self.apk_file)
        
            # Simulate user interactions
            if not self.installed:
                self.log("Closing emulator. Once closed, select 'Dynamic Analysis' to run again.")
                subprocess.run(["adb", "emu", "kill"])
            else:
                self.simulate_interactions(self.apk_file)
            
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
        time.sleep(90)  # adb connection delay 
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
            

    def install_apk(self, apk_file, max_retries=3):
        """Install the APK on the emulator."""
        retries = 0
        self.log(f"Installing APK: {apk_file}")
        while retries < max_retries:
            try:
                install_command = ["adb", "install", apk_file]
                result = subprocess.run(install_command, capture_output=True, text=True)    
                if result.returncode == 0:
                    self.apk_installed.emit()   
                    self.installed = True
                    return self.installed           
                else:
                    retries += 1
                    self.log(f"Failed to install APK: {result.stderr}\nRetrying install.")
                    time.sleep(15)                   
            except Exception as e:
                    retries += 1
                    self.log(f"Failed to install APK: {result.stderr}\nRetrying install.")
                    time.sleep(15)
                    
        self.error.emit(f"Failed to install APK after {max_retries} retries.")


    def get_package_name(self, apk_file):
        """Looks in manifest permissions file to get the package name of APK."""
        # Analyze the APK
        a, d, dx = AnalyzeAPK(apk_file)
        # Get the package name
        package_name = a.get_package()
        if package_name:
            return package_name
        else:
             self.log("Package name not found.")


    def simulate_interactions(self, apk_file ):
        """Simulate user interactions using Monkey."""

        self.log("Preparing to simulate user interactions...")
        #Get package name 
        package_name = self.get_package_name(apk_file)
        # Monkey testing settings
        monkey_events = 100  # Number of events to simulate
        self.log("Simulating user interactions...")
        try:
            # ADB command for Monkey testing
            monkey_command = f"adb shell monkey -v -p {package_name} {monkey_events}"
            # Run Monkey testing
            result = subprocess.run(monkey_command, capture_output=True, text=True, shell=True)
            # Check result
            if result.returncode == 0:
                #self.log("Monkey testing completed.")
                self.monkey_test.emit()
            else:
                self.log(f"Monkey testing failed: {result.stderr}")       
        except Exception as e:
            self.error.emit(f"Error simulating interactions: {e}")

