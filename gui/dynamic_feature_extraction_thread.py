#######################################################################################
#                       Emulator Setup & Dynamic Feature Extraction                   #                       
#######################################################################################
'''
Executes the dynamic analysis workflow by starting the emulator, installing the APK, 
and performing network activity logging and simulated user interactions.
'''
import subprocess 
import time 
from androguard.misc import AnalyzeAPK 
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
    monkey_test = pyqtSignal() # Signal when user interaction simulation is compelted
    log_signal = pyqtSignal(str)  # Signal to send log messages to the main UI
    pcap_loaded_to_host = pyqtSignal(str) # Signal to send when pcap is exported to host 
    

    def __init__(self, emulator_dir, emulator_command, adb_command, apk_file, adb_path):
        super().__init__()
        self.emulator_dir = emulator_dir
        self.emulator_command = emulator_command
        self.adb_command = adb_command
        self.apk_file = apk_file
        self.installed  = False 
        self.adb_path = adb_path
        self.adb_root_shell_access = False
        self.duration = 60
        self.tcpdump_emu_pcap_file = "emu_tcpdump_results"
        self.emu_tcpdump_file_path = f"data/local/tmp/{self.tcpdump_emu_pcap_file}"
        self.pcap_file_location_on_host = self.tcpdump_emu_pcap_file
         
    def run(self):
        """
        Executes the dynamic analysis workflow by starting the emulator, installing the APK, 
        and performing network activity logging and simulated user interactions.

        This method is designed to be executed in a separate thread, handling the following tasks sequentially:
        
        Workflow:
            1. Start Emulator: Launches the Android emulator for analysis.
            2. Check Emulator Status: Verifies that the emulator is ready for operations.
            3. Install APK: Installs the selected APK on the emulator.
                - If the installation fails, the emulator is stopped, and the user is prompted to retry.
            4. Grant ADB Root Access: Attempts to enable ADB root access on the emulator.
                - Logs a failure message if root access cannot be granted.
            5. Extract Package Name: Parses the APK file to obtain the package name, used for Monkey testing.
            6. Simulate User Interactions:
                - Starts `tcpdump` for network logging.
                - Runs Monkey testing to simulate user interactions.
                - Stops `tcpdump` after interactions are completed.
            7. Pull Logs: Transfers the captured network activity logs (.pcap) from the emulator to the host.
            8. Emit Signal: Signals the host that the logs have been successfully transferred.
            """
        try:
            
            # Start emulator
            self.start_emulator()

            # Check emulator status
            self.check_emulator_ready()

            # Install APK only if emulator is running
            self.install_apk(self.apk_file)
       
            # Stop dynamic anlysis procsses if APK does not install 
            if not self.installed:
                self.log("Closing emulator. Once closed, select 'Dynamic Analysis' to run again.")
                subprocess.run([self.adb_path, "emu", "kill"])
            else:
                # Grant ADB root access
                self.adb_root()
                if not self.adb_root_shell_access:
                    self.log("Failed: adb root access.")
                else:
                    self.log("Getting package name for simulated user interactions...")

            #Get package name from Manifest Permissions File. This will be used for monkey.
            package_name = self.get_package_name(self.apk_file)

           
            #Start tcpdump, run monkey, then stop tcpdump.
            self.start_tcpdump_and_run_monkey(package_name, self.duration)

            self.pull_logs_from_emu(self.adb_path, self.emu_tcpdump_file_path, self.pcap_file_location_on_host)

            self.pcap_loaded_to_host.emit(f"{self.pcap_file_location_on_host}")

        except Exception as e:
            self.error.emit(str(e))
    
    #######################################################################################
    #                                  Emulator Setup                                     #                       
    #######################################################################################
    '''
    These functions prepare the emulator for dynamic analysis of Android applications,
    covering:

    1. Emulator management (start, check readiness)
    2. APK installation and verification
    3. ADB root access
    4. Package name extraction
    5. Simulated user interactions using Monkey testing
    '''

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
        time.sleep(30)  # Sleep to handle adb connection delay 90 for now 
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

    def adb_root(self):
        try:
            # Execute adb root command
            root_command = [self.adb_path, "root"]
            result = subprocess.run(root_command, capture_output=True, text=True, check=False)

            if result.returncode != 0:
                self.error.emit(f"Failed to execute adb root: {result.stderr}")
                return False  # adb root failed

            # Wait a short period to allow adb root to take effect
            time.sleep(5)

            # Verify success using 'adb shell id'
            id_command = [self.adb_path, "shell", "id"]
            
            # Retry multiple times in case it takes a moment to switch to root mode
            for _ in range(5):  # Try 5 times with a small delay
                result = subprocess.run(id_command, capture_output=True, text=True, check=True)
                
                # Check if the output contains 'uid=0(root)'
                if "uid=0(root)" in result.stdout:
                    self.adb_root_shell_access = True
                    self.log("Root access granted.")
                    return True  # Root access granted
                
                # If not in root mode, wait for a short period before retrying
                time.sleep(5)  # Adjust the sleep time as needed

            # If after retries, still no root access
            self.error.emit(f"Failed to get root access. Current user ID: {result.stdout.strip()}")
            return False

        except Exception as e:
            self.error.emit(f"An error occurred while checking adb root: {e}")
            return False

    
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

   
    #######################################################################################
    #                                  tcpdump & monkey                                   #                       
    #######################################################################################
    '''
    Captures network traffic generated by the app using the tcpdump tool. 
    Runs Monkey testing to simulate user interactions.
    '''
    def start_tcpdump_and_run_monkey(self, package_name, duration):
        try:
            # Start adb shell to prepare for tcpdump and Monkey testing
            adb_shell = [self.adb_path, "shell"]
            adb_shell_process = subprocess.Popen(adb_shell, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # Echange to /data/local/tmp
            adb_shell_process.stdin.write(b"cd /data/local/tmp\n")
            adb_shell_process.stdin.flush()

            # Run pwd to print the current directory and log the output
            adb_shell_process.stdin.write(b"pwd\n")
            adb_shell_process.stdin.flush()

            # Start tcpdump in the background inside the adb shell
            tcpdump_command = (f"tcpdump -i any -p -s 0 -vv -t -U -w {self.tcpdump_emu_pcap_file}\n")

            #tcpdump_command = "tcpdump -i any -p -s 0 -vv -t -U -w /data/local/tmp/tcpdump_results &\n"
            adb_shell_process.stdin.write(tcpdump_command.encode())
            adb_shell_process.stdin.flush()

            # Log that tcpdump has started
            self.log_signal.emit("Tcpdump started")

            # Simulate user interactions with Monkey
            self.log("Simulating user interactions with Monkey...")
            monkey_events = 4  # Number of events to simulate
            monkey_command = f"adb shell monkey -v -p {package_name} {monkey_events}"

            # Run Monkey testing while tcpdump is capturing traffic
            result = subprocess.run(monkey_command, capture_output=True, text=True, shell=True)

            if result.returncode == 0:
                self.monkey_test.emit()  # Emit the signal when Monkey test completes
            else:
                self.log(f"Monkey simulations failed: {result.stderr}")

            # Allow tcpdump to run for the duration of the test
            time.sleep(duration)

            # Stop tcpdump
            stop_tcpdump_command = "pkill tcpdump\n"
            adb_shell_process.stdin.write(stop_tcpdump_command.encode())
            adb_shell_process.stdin.flush()

            # Wait for the tcpdump process to finish
            self.log_signal.emit(f"Tcpdump stopped. File created: {self.tcpdump_emu_pcap_file}")

            # Exit adb shell
            adb_shell_process.stdin.write(b"exit\n")
            adb_shell_process.stdin.flush()

        except Exception as e:
            self.error.emit(f"Error running tcpdump and Monkey simulations: {str(e)}")
   
    #######################################################################################
    #                             Pull Logs From Emulator                                 #                       
    #######################################################################################
    '''
    Pulls the pcap file to the host machine.
    '''
    def pull_logs_from_emu(self, adb_path, emu_tcpdump_file_path, pcap_file_location_on_host): 
        try:
                # Construct the adb pull command
                command = [adb_path, "pull", emu_tcpdump_file_path, pcap_file_location_on_host]
                
                # Run the command and capture the output
                result = subprocess.run(command, capture_output=True, text=True)

                # Check for errors in the result
                if result.returncode == 0:
                    self.log_signal.emit(f"Successfully pulled the file: {pcap_file_location_on_host}. Ready for Tshark extraction and formatting.")
                else:
                    self.log_signal.emit(f"Failed to pull the file. Error: {result.stderr}")
            
        except Exception as e:
            self.log_signal.emit(f"An error occurred while pulling the tcpdump file: {str(e)}")

    

    