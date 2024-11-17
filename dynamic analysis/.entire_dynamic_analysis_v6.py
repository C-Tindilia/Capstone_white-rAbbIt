import subprocess # This provides an interface to spawn new processes, connect to their input/output/error pipes, and obtain their return codes. Running ADB to interact Android device and tools.
import time # Provides time-related functions.
import logging # Used to log messages, errors, and warnings to the console to provide insight into the program's execution.
import json # Used to save analysis results (dynamic features) into a JSON file for structured data storage and future reference.
import os # Used to construct file paths, create directories, check for the existence of files, and interact with the file system.
import sys # Used for handling program exits (sys.exit()) when critical errors occur, such as missing dependencies or failed APK installations.
from threading import Lock # Used to manage concurrent updates to the dynamic_features dictionary when multiple threads are collecting data simultaneously.
from tkinter import Tk, filedialog # Used to create a pop-up file dialog (filedialog.askopenfilename()) for selecting an APK file, enhancing usability for non-command-line-savvy users.
from androguard.misc import AnalyzeAPK # Used to extract the package name from the APK file.

# Configure logging format and level
# Logs will show thread names and relevant messages for debugging and tracking
logging.basicConfig(level=logging.INFO, format='%(threadName)s: %(message)s')

class DependencyChecker:
    """
    Class to perform dependency and environment checks required for the analysis.
    It ensures that both host and device dependencies are installed and available
    """
    # Required tools for the host machine and Android device
    REQUIRED_HOST_TOOLS = ['adb', 'tshark']
    REQUIRED_DEVICE_TOOLS = ['strace', 'inotifywait', 'tcpdump']


    def __init__(self, adb_path='adb'):
        """
        Initialize the DependencyChecker with the path to the adb tool.
        """
        self.adb_path = adb_path


    def is_tool_installed(self, tool_name):
        """ 
        Check if a tool is installed and available in the PATH on the host machine.
        Check whether `tool_name` is on PATH and marked as executable.
        """
        from shutil import which
        return which(tool_name) is not None



    def is_device_connected(self):
        """
        Check if an Android device is connected and accessible through adb.
        """
        try:
            result = subprocess.run([self.adb_path, 'devices'], capture_output=True, text=True)
            # Parse the device list and ensure at least one device is connected
            devices = result.stdout.strip().split('\n')[1:]
            return any('device' in device for device in devices)
        except Exception as e:
            logging.error(f"Failed to check device connection: {e}")
            return False

    def is_device_rooted(self):
        """Check if the connected Android device is shell."""
        try:
            result = subprocess.run([self.adb_path, 'shell', 'id'], capture_output=True, text=True)
            return 'uid=0' in result.stdout # Root user ID is 0 | Shell user ID is 1
        except Exception as e:
            logging.error(f"Failed to check if device is shell: {e}")
            return False

    def is_device_tool_installed(self, tool_name):
        """Check if a required tool is installed on the Android device."""
        try:
            result = subprocess.run([self.adb_path, 'shell', 'which', tool_name], capture_output=True, text=True)
            return tool_name in result.stdout.strip()
        except Exception as e:
            logging.error(f"Failed to check if {tool_name} is installed on device: {e}")
            return False

    def install_missing_device_tools(self, tools):
        """
        Install any missing tools on the Android device.
        Also ensures the libc++_shared.so library is present for tool dependencies.
        """
        libc_path = '/home/whiterabbit/Android/android-ndk-r27c/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/x86_64-linux-android/libc++_shared.so'
        target_libc_path = '/data/local/tmp/libc++_shared.so'

        # Ensure libc++_shared.so is available on the device
        if not os.path.isfile(libc_path):
            logging.error(f"libc++_shared.so not found at {libc_path}. Please verify its location.")
            sys.exit(1)
            
        try:
            logging.info("Pushing libc++_shared.so to the device...")
            subprocess.run([self.adb_path, 'push', libc_path, target_libc_path], check=True)
            subprocess.run([self.adb_path, 'shell', 'chmod', '755', target_libc_path], check=True)
            logging.info("libc++_shared.so installed successfully.")
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to push libc++_shared.so: {e}")
            sys.exit(1)

        # Iterate through the missing tools and attempt installation
        for tool in tools:
            tool_binary = os.path.join('/home/whiterabbit/tools_dy', tool, 'src', tool)
            if not os.path.isfile(tool_binary):
                logging.error(f"{tool} binary not found in /home/whiterabbit/tools_dy/{tool}/src.")
                continue  # Skip tool instead of exiting
            try:
                subprocess.run([self.adb_path, 'push', tool_binary, f'/data/local/tmp/{tool}'], check=True)
                subprocess.run([self.adb_path, 'shell', 'chmod', '755', f'/data/local/tmp/{tool}'], check=True)
                logging.info(f"{tool} installed successfully.")
            except subprocess.CalledProcessError as e:
                logging.error(f"Failed to install {tool}: {e}")

    def perform_checks(self):
        """
        Perform all necessary dependency and environment checks before running the analysis.
        Checks:
        1. Ensure host tools are installed.
        2. Ensure a device is connected.
        3. Ensure required device tools and libraries are available.
        """
        # Check if required host tools are installed
        missing_host_tools = [tool for tool in self.REQUIRED_HOST_TOOLS if not self.is_tool_installed(tool)]
        if missing_host_tools:
            logging.error(f"Missing required host tools: {', '.join(missing_host_tools)}")
            sys.exit(1)
        logging.info("All required host tools are installed.")

        # Check if the device is connected
        if not self.is_device_connected():
            logging.error("No Android device connected. Please connect a device and try again.")
            sys.exit(1)
        logging.info("Android device is connected.")

        # Check if libc++_shared.so is present on the device
        result = subprocess.run([self.adb_path, 'shell', 'ls', '/data/local/tmp/libc++_shared.so'], capture_output=True, text=True)
        if 'No such file or directory' in result.stdout:
            logging.warning("libc++_shared.so not found on device. Attempting to push it...")
            self.install_missing_device_tools([])  # Push only the libc++_shared.so if needed
        else:
            logging.info("libc++_shared.so is present on the device.")

        # Check if required device tools are installed
        missing_device_tools = [tool for tool in self.REQUIRED_DEVICE_TOOLS if not self.is_device_tool_installed(tool)]
        if missing_device_tools:
            logging.warning(f"Missing required device tools: {', '.join(missing_device_tools)}")
            logging.info("Attempting to install missing device tools...")
            self.install_missing_device_tools(missing_device_tools)
        else:
            logging.info("All required device tools are installed.")

class DynamicAnalysisFramework:
    """
    Main class for performing dynamic analysis on an Android app.
    Includes functionality to:
    1. Select and install an APK.
    2. Perform various monitoring tasks (e.g., logs, system calls, file system, and network).
    3. Save analysis results for further processing.
    """

    def __init__(self, package_name=None, duration=30, adb_path='adb'):
        """
        Initialize the framework with optional package name, analysis duration, and adb path.
        Creates output folders for storing results and logs.
        """
        self.package_name = package_name
        self.duration = duration
        self.adb_path = adb_path
        self.dynamic_features = {}
        self.dynamic_features_lock = Lock()
        self.dependency_checker = DependencyChecker(adb_path=self.adb_path)

        # Create a timestamped folder for output files
        self.OUTPUT_FOLDER = os.path.join('/home/whiterabbit/dynamic_analysis_results', time.strftime('%Y%m%d_%H%M%S')) 
        os.makedirs(self.OUTPUT_FOLDER, exist_ok=True)
        self.LOG_FILE_PATH = os.path.join(self.OUTPUT_FOLDER,'dynamic_Analysis_log.txt')
        self.STRACE_LOCAL_OUTPUT = os.path.join(self.OUTPUT_FOLDER,'strace_output.txt')
        self.FILESYSTEM_OUTPUT_FILE = os.path.join(self.OUTPUT_FOLDER,'filesystem_changes.txt')
        self.TCPDUMP_LOCAL_PCAP_FILE = os.path.join(self.OUTPUT_FOLDER,'network_capture.pcap')
        self.DIRECTORY_TO_MONITOR = os.path.join(self.OUTPUT_FOLDER,'directory_monitoring.txt')

    def check_app_installed(self):
        """
        Check if the app is installed on the device.
        Returns True if installed, False otherwise.
        """
        try:
            result = subprocess.run([self.adb_path, 'shell', 'pm', 'list', 'packages'], capture_output=True, text=True)
            if self.package_name in result.stdout:
                logging.info(f"Package {self.package_name} is installed.")
                return True
            else:
                logging.warning(f"Package {self.package_name} is not installed.")
                return False
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to check if app is installed: {e}")
            return False


    def select_apk_file(self):
        """
        Open a file dialog to allow the user to select an APK file.
        Uses Tkinter's `filedialog` module for the GUI.
        """
        root = Tk() # Create the Tkinter root widget
        root.withdraw() # Hide the root window
        apk_file = filedialog.askopenfilename(
            title="Select APK File",
            filetypes=[("APK Files", "*.apk")], # Filter to show only APK files
            initialdir=os.path.expanduser("~")  # Start from the user's home directory
        )
        return apk_file

    def get_package_name(self, apk_file):
        """
        Use androguard to extract the package name from the selected APK file.
        """
        try:
            a, d, dx = AnalyzeAPK(apk_file) # Analyze the APK
            package_name = a.get_package()  # Extract package name
            if package_name:
                return package_name
        except Exception as e:
            logging.error(f"Failed to analyze APK: {e}")
        return None

    def install_app(self, apk_path):
        """
        Install the specified APK on the Android device.
        Uninstalls any existing version of the app before reinstallation.
        """
        if not os.path.isfile(apk_path):
            logging.error(f"APK file not found at {apk_path}.")
            sys.exit(1)

        # Check and uninstall existing app if needed
        try:
            result = subprocess.run([self.adb_path, 'shell', 'pm', 'list', 'packages'], capture_output=True, text=True)
            if self.package_name in result.stdout:
                logging.info(f"Package {self.package_name} is already installed. Attempting to uninstall it first...")
                subprocess.run([self.adb_path, 'uninstall', self.package_name], check=True)
                logging.info(f"Uninstalled {self.package_name}.")
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to uninstall existing app: {e}")
            sys.exit(1)

        # Install the new APK
        try:
            logging.info(f"Installing APK from {apk_path}...")
            subprocess.run([self.adb_path, 'install', apk_path], check=True)
            logging.info(f"APK installed successfully: {apk_path}")
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to install APK: {e}")
            sys.exit(1)

    def launch_app(self):
        """
        Launch the installed app on the device using adb's monkey tool.
        """
        try:
            subprocess.run([self.adb_path, 'shell', 'monkey', '-p', self.package_name, '-c', 'android.intent.category.LAUNCHER', '1'], check=True)
            logging.info(f'Launched app {self.package_name}')
            time.sleep(2)  # Wait for the app to start
        except Exception as e:
            logging.error(f"Failed to launch app: {e}")

    # Stage 1: Log Collection
    class LogCollector:
        """
        Collects logs from the Android device using logcat.
        Extracts error and warning counts from the logs and saves them to the dynamic features dictionary.
        """
        def __init__(self, adb_path, log_file_path, duration, dynamic_features, lock):
            self.adb_path = adb_path
            self.log_file_path = log_file_path
            self.duration = duration
            self.dynamic_features = dynamic_features
            self.lock = lock

        def start_logcat(self):
            """
            Start collecting logs using adb logcat and write them to a file.
            """
            try:
                log_file = open(self.log_file_path, 'w')
                process = subprocess.Popen([self.adb_path, 'logcat', '-v', 'time'], stdout=log_file, stderr=subprocess.STDOUT)
                return process, log_file
            except Exception as e:
                logging.error(f"Failed to start logcat: {e}")
                return None, None

        def stop_logcat(self, process, log_file):
            """
             Stop the logcat process and close the log file.
            """
            if process:
                process.terminate()
                process.wait()
            if log_file:
                log_file.close()

        def parse_log_file(self):
            """
            Analyze the collected log file to count errors and warnings.
            """
            error_count = 0
            warning_count = 0
            try:
                with open(self.log_file_path, 'r') as f:
                    for line in f:
                        if 'ERROR' in line: # Check for errors
                            error_count += 1
                        if 'WARNING' in line: # Check for warnings
                            warning_count += 1
                # Update dynamic features safely            
                with self.lock:
                    self.dynamic_features['log_errors'] = error_count
                    self.dynamic_features['log_warnings'] = warning_count
            except Exception as e:
                logging.error(f"Failed to parse log file: {e}")

        def run(self):
            """
            Perform the log collection process:
            1. Start logcat.
            2. Collect logs for the specified duration.
            3. Stop logcat and analyze logs.
            """
            logging.info('Starting logcat...')
            logcat_process, log_file = self.start_logcat()
            if not logcat_process:
                logging.error('Logcat process failed to start.')
                return
            try:
                logging.info(f'Collecting logs for {self.duration} seconds...')
                time.sleep(self.duration)
            finally:
                logging.info('Stopping logcat...')
                self.stop_logcat(logcat_process, log_file)
                logging.info(f'Logs saved to {self.log_file_path}')
                self.parse_log_file()

    # Stage 2: System Call Monitoring
    class SystemCallMonitor:
        """
        Monitors system calls made by the app using the strace tool.
        Tracks overall system call counts, file access calls, and network calls.
        """
        def __init__(self, adb_path, package_name, strace_local_output, duration, dynamic_features, lock):
            self.adb_path = adb_path
            self.package_name = package_name
            self.strace_local_output = strace_local_output
            self.duration = duration
            self.dynamic_features = dynamic_features
            self.lock = lock

        def get_app_pid(self):
            """
            Retrieve the process ID (PID) of the app based on its package name.
            """
            try:
                result = subprocess.run([self.adb_path, 'shell', f'pidof {self.package_name}'], capture_output=True, text=True)
                pid = result.stdout.strip()
                if pid:
                    logging.info(f'PID of {self.package_name}: {pid}')
                    return pid
                else:
                    logging.warning(f'Application {self.package_name} is not running.')
                    return None
            except Exception as e:
                logging.error(f"Failed to get PID: {e}")
                return None

        def start_strace(self, pid):
            """
            Start the strace tool for the specified PID.
            """
            try:
                command = f'/data/local/tmp/strace -p {pid} -o {self.strace_local_output}'
                process = subprocess.Popen([self.adb_path, 'shell', command], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                return process
            except Exception as e:
                logging.error(f"Failed to start strace: {e}")
                return None

        def stop_strace(self, process):
            """
            Stop the strace tool and clean up processes on the device.
            """
            if process:
                subprocess.run([self.adb_path, 'shell', 'pkill', 'strace'])
                process.terminate()
                process.wait()

        def pull_strace_output(self):
            """No longer pulls from '/sdcard'. Log is directly in local directory"""
            logging.info(f'Strace output is already in {self.strace_local_output}')

        def parse_strace_output(self):
            """
            Analyze the strace output file to extract system call statistics.
            """
            system_call_count = 0
            file_access_calls = 0
            network_calls = 0
            try:
                with open(self.strace_local_output, 'r') as f:
                    for line in f:
                        system_call_count += 1
                        if 'open' in line or 'read' in line or 'write' in line:
                            file_access_calls += 1
                        if 'connect' in line or 'send' in line or 'recv' in line:
                            network_calls += 1
                # Update dynamic features safely
                with self.lock:
                    self.dynamic_features['system_calls_count'] = system_call_count
                    self.dynamic_features['file_access_calls'] = file_access_calls
                    self.dynamic_features['network_calls'] = network_calls
            except Exception as e:
                logging.error(f"Failed to parse strace output: {e}")

        def run(self):
            """
            Perform system call monitoring:
            1. Get the app's PID.
            2. Start strace for the app's PID.
            3. Collect data for the specified duration.
            4. Stop strace and analyze the results.
            """
            pid = self.get_app_pid()
            if not pid:
                logging.warning('Skipping system call monitoring as the app is not running.')
                return
            logging.info(f'Starting strace on PID {pid}...')
            strace_process = self.start_strace(pid)
            if not strace_process:
                logging.error('Strace process failed to start.')
                return
            try:
                logging.info(f'Monitoring system calls for {self.duration} seconds...')
                time.sleep(self.duration)
            finally:
                logging.info('Stopping strace...')
                self.stop_strace(strace_process)
                logging.info('Pulling strace output to local machine...')
                self.pull_strace_output()

    # Stage 3: File System Monitoring
    class FileSystemMonitor:
        """
        Monitors file system changes on the Android device using the inotifywait tool.
        Tracks file creations and deletions.
        """
        def __init__(self, adb_path, directory_to_monitor, filesystem_output_file, duration, dynamic_features, lock):
            self.adb_path = adb_path
            self.directory_to_monitor = directory_to_monitor
            self.filesystem_output_file = filesystem_output_file
            self.duration = duration
            self.dynamic_features = dynamic_features
            self.lock = lock

        def start_inotifywait(self):
            """
            Starts inotifywait on the device to monitor the specified directory for file changes.
            """
            try:
                command = f'LD_LIBRARY_PATH=/data/local/tmp /data/local/tmp/inotifywait -m -r {self.directory_to_monitor}'
                outfile = open(self.filesystem_output_file, 'w')
                process = subprocess.Popen([self.adb_path, 'shell', command], stdout=outfile, stderr=subprocess.STDOUT)
                return process, outfile
            except Exception as e:
                logging.error(f"Failed to start inotifywait: {e}")
                return None, None

        def stop_inotifywait(self, process, outfile):
            """
            Stop the inotifywait process and clean up resources.
            """
            if process:
                subprocess.run([self.adb_path, 'shell', 'pkill', 'inotifywait'])
                process.terminate()
                process.wait()
            if outfile:
                outfile.close()

        def parse_filesystem_changes(self):
            """
            Analyze the file system monitoring output to count file creations and deletions.
            """
            files_created = 0
            files_deleted = 0
            try:
                with open(self.filesystem_output_file, 'r') as f:
                    for line in f:
                        if 'CREATE' in line:
                            files_created += 1
                        if 'DELETE' in line:
                            files_deleted += 1
                # Update dynamic features safely
                with self.lock:
                    self.dynamic_features['files_created'] = files_created
                    self.dynamic_features['files_deleted'] = files_deleted
            except Exception as e:
                logging.error(f"Failed to parse filesystem changes: {e}")

        def run(self):
            """
            Perform file system monitoring:
            1. Start inotifywait for the specified directory.
            2. Collect data for the specified duration.
            3. Stop inotifywait and analyze the results.
            """
            logging.info(f'Starting file system monitoring on {self.directory_to_monitor}...')
            inotify_process, outfile = self.start_inotifywait()
            if not inotify_process:
                logging.error('Inotifywait process failed to start.')
                return
            try:
                logging.info(f'Monitoring file system for {self.duration} seconds...')
                time.sleep(self.duration)
            finally:
                logging.info('Stopping file system monitoring...')
                self.stop_inotifywait(inotify_process, outfile)
                logging.info(f'File system changes saved to {self.filesystem_output_file}')
                self.parse_filesystem_changes()

    # Stage 4: Network Capture
    class NetworkCapture:
        """
        Captures network traffic generated by the app using the tcpdump tool.
        Analyzes the captured PCAP file for network statistics.
        """
        def __init__(self, adb_path, tcpdump_local_pcap_file, duration, dynamic_features, lock):
            self.adb_path = adb_path
            self.tcpdump_local_pcap_file = tcpdump_local_pcap_file
            self.duration = duration
            self.dynamic_features = dynamic_features
            self.lock = lock

        def start_tcpdump(self):
            """
            Start the tcpdump tool to capture network traffic.
            """
            try:
                #tcpdump_command = f'/data/local/tmp/tcpdump -i any -p -s 0 -w {self.tcpdump_local_pcap_file}'
                tcpdump_command = f'tcpdump -i any -p -s 0 -w {self.tcpdump_local_pcap_file}'
                process = subprocess.Popen([self.adb_path, 'shell', tcpdump_command], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                return process
            except Exception as e:
                logging.error(f"Failed to start tcpdump: {e}")
                return None

        def stop_tcpdump(self, process):
            """
            Stop the tcpdump process and clean up resources.
            """
            if process:
                subprocess.run([self.adb_path, 'shell', 'pkill', 'tcpdump'])
                process.terminate()
                process.wait()

        def pull_pcap_file(self):
            """No longer pulls from '/sdcard', PCAP is directly in the local machine."""
            logging.info(f'PCAP file already in {self.tcpdump_local_pcap_file}')
            
        def parse_pcap_file(self):
            """
            Analyze the PCAP file to extract network traffic statistics.
            """
            network_connections = 0
            data_sent = 0
            data_received = 0
            try:
                result = subprocess.run(['tshark', '-r', self.tcpdump_local_pcap_file, '-qz', 'io,stat,0'], capture_output=True, text=True)
                for line in result.stdout.splitlines():
                    if '|' in line and 'Frames' in line:
                        fields = line.split('|')
                        if len(fields) > 5:
                            network_connections += int(fields[2].strip())
                            data_sent += int(fields[5].strip())
                            data_received += int(fields[6].strip())
                # Update dynamic features safely
                with self.lock:
                    self.dynamic_features['network_connections'] = network_connections
                    self.dynamic_features['data_sent_bytes'] = data_sent
                    self.dynamic_features['data_received_bytes'] = data_received
            except Exception as e:
                logging.error(f"Error parsing pcap file: {e}")

        def run(self):
            """
            Perform network capture:
            1. Start tcpdump.
            2. Collect network traffic for the specified duration.
            3. Stop tcpdump and analyze the results.
            """
            logging.info('Starting tcpdump on device...')
            tcpdump_process = self.start_tcpdump()
            if not tcpdump_process:
                logging.error('tcpdump process failed to start.')
                return
            try:
                logging.info(f'Capturing network traffic for {self.duration} seconds...')
                time.sleep(self.duration)
            finally:
                logging.info('Stopping tcpdump on device...')
                self.stop_tcpdump(tcpdump_process)
                logging.info('Pulling pcap file to local machine...')
                self.pull_pcap_file()


    def run_analysis(self):
        """
        Runs the dynamic analysis sequentially.
        """
        logging.info("Starting Dynamic Analysis Framework...")

        # Perform dependency and environment checks
        self.dependency_checker.perform_checks()

        # Check if the app is installed
        app_installed = self.check_app_installed()

        # Launch the app if installed
        if app_installed:
            self.launch_app()
        else:
            logging.info('Proceeding without launching the app.')

        # Stage 1: Log Collection
        log_collector = self.LogCollector(
            adb_path=self.adb_path,
            log_file_path=self.LOG_FILE_PATH,
            duration=self.duration,
            dynamic_features=self.dynamic_features,
            lock=self.dynamic_features_lock
        )
        log_collector.run()

        # Stage 2: System Call Monitoring
        syscall_monitor = self.SystemCallMonitor(
            adb_path=self.adb_path,
            package_name=self.package_name,
            #strace_output_on_device=self.STRACE_OUTPUT_ON_DEVICE,
            strace_local_output=self.STRACE_LOCAL_OUTPUT,
            duration=self.duration,
            dynamic_features=self.dynamic_features,
            lock=self.dynamic_features_lock
        )
        syscall_monitor.run()

        # Stage 3: File System Monitoring
        fs_monitor = self.FileSystemMonitor(
            adb_path=self.adb_path,
            directory_to_monitor=self.DIRECTORY_TO_MONITOR,
            filesystem_output_file=self.FILESYSTEM_OUTPUT_FILE,
            duration=self.duration,
            dynamic_features=self.dynamic_features,
            lock=self.dynamic_features_lock
        )
        fs_monitor.run()

        # Stage 4: Network Capture
        network_capture = self.NetworkCapture(
            adb_path=self.adb_path,
            #tcpdump_device_pcap_file=self.TCPDUMP_DEVICE_PCAP_FILE,
            tcpdump_local_pcap_file=self.TCPDUMP_LOCAL_PCAP_FILE,
            duration=self.duration,
            dynamic_features=self.dynamic_features,
            lock=self.dynamic_features_lock
        )
        network_capture.run()

        logging.info("Dynamic Analysis Completed!")

        # Save dynamic features to a JSON file
        self.save_dynamic_features()

    def save_dynamic_features(self):
        """Save dynamic features to a JSON file."""
        output_file = os.path.join(self.OUTPUT_FOLDER, 'dynamic_features.json')
        try:
            with open(output_file, 'w') as outfile:
                json.dump(self.dynamic_features, outfile, indent=4)
            logging.info(f"Dynamic features saved to {output_file}")
        except Exception as e:
            logging.error(f"Failed to save dynamic features: {e}")

if __name__ == '__main__':
    logging.info("Starting APK analysis setup...")

    # Create a framework instance without a package name initially
    framework = DynamicAnalysisFramework(duration=30)

    # Prompt the user to select an APK file
    apk_path = framework.select_apk_file()
    if not apk_path:
        logging.error("No APK file selected. Exiting.")
        sys.exit(1)

    # Analyze the APK to get the package name
    package_name = framework.get_package_name(apk_path)
    if not package_name:
        logging.error("Failed to extract package name from APK. Exiting.")
        sys.exit(1)

    logging.info(f"Package name extracted: {package_name}")
    framework.package_name = package_name

    # Install the APK on the device
    framework.install_app(apk_path)

    # Run the dynamic analysis
    framework.run_analysis()




