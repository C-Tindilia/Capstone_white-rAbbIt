##
## The code will run sequentially in this order:
##      Check if APK is installed and launched then,
##      Stage 1: Log Collection for 60 seconds, then stops it.
##      Stage 2: System Call Monitoring for 60 seconds, then stops it.
##      Stage 3: File System Monitoring for 60 seconds, then stops it.
##      Stage 4: Network Capture for 60 seconds, then stops it.
##

import subprocess  # Allows execution of system commands from within the Python script
import time  # Used to introduce delays in the script, such as sleep timers between operations

# Define paths, globally for easier modification and maintainability 
ADB_PATH = 'adb'  # Path to the adb executable. This can be changed if adb is not in the system PATH
LOG_FILE_PATH = 'dynamic_Analysis_log.txt'  # File where logcat output will be saved
PACKAGE_NAME = 'com.example.malwareapp'  # represent package name of the APK we loading in the emulator| defined in the app's manifest files
STRACE_OUTPUT_ON_DEVICE = '/sdcard/strace_output.txt'  # Path on the Android device where strace output is saved
STRACE_LOCAL_OUTPUT = 'strace_output.txt'  # Path on the local machine where the strace output will be pulled
DIRECTORY_TO_MONITOR = '/sdcard'  # Directory on the Android device to monitor for file system changes
FILESYSTEM_OUTPUT_FILE = 'filesystem_changes.txt'  # File to store file system monitoring output
TCPDUMP_LOCAL_PCAP_FILE = 'network_capture.pcap'  # File where captured network traffic will be saved on the local machine
TCPDUMP_DEVICE_PCAP_FILE = '/sdcard/network_capture.pcap'  # File where network traffic will be saved on the Android device
DURATION = 60  # Duration for monitoring tasks, set to 60 seconds for each stage

# STAGE 1: LOG CAPTURE
def start_logcat(log_file_path):
    """
    Starts logcat and writes logs to the specified file.
    Logs important events, errors, and messages from the Android system and apps.
    """
    with open(log_file_path, 'w') as log_file:  # Open the log file for writing
        # Start logcat process using adb to capture logs in real-time
        process = subprocess.Popen([ADB_PATH, 'logcat', '-v', 'time'], stdout=log_file, stderr=subprocess.STDOUT)
        return process  # Return the logcat process for later termination

def stop_logcat(process):
    """
    Stops the logcat process.
    Properly terminates the log collection process to avoid data corruption.
    """
    process.terminate()  # Terminate the logcat process
    process.wait()  # Wait until the process is fully stopped

def log_collecting_main():
    print('Starting logcat...')
    logcat_process = start_logcat(LOG_FILE_PATH)  # Start log collection and save logs to a file
    try:
        print(f'Collecting logs for {DURATION} seconds...')
        time.sleep(DURATION)  # Collect logs for the specified duration (60 seconds)
    finally:
        print('Stopping logcat...')
        stop_logcat(logcat_process)  # Stop the log collection process after the duration
        print(f'Logs saved to {LOG_FILE_PATH}')
        
    #TODO:Reference Dictionary:
    #dynamic_features['log_file'] = LOG_FILE_PATH  # Store log file path


# STAGE 2: SYSTEM CALL MONITORING
# PID (Process ID) each running process has unique identifier
# So monitoring a specific process it is referred as a PID
def get_app_pid(package_name):
    """
    Retrieves the PID of the application based on its package name.
    Useful for targeting a specific running app for system call monitoring.
    """
    result = subprocess.run([ADB_PATH, 'shell', f'pidof {package_name}'], capture_output=True, text=True)  # Run ADB command to get PID
    pid = result.stdout.strip()  # Extract the PID from the command output
    if pid:
        print(f'PID of {package_name}: {pid}')  # Print the PID if found
        return pid
    else:
        print(f'Application {package_name} is not running.')  # Inform if the app is not running
        return None  # Return None if the app is not running

# strace: traces and logs the system calls
def start_strace(pid, output_file):
    """
    Starts strace on the device for the specified PID.
    Strace is used to track system calls made by the app to detect potential malicious behavior.
    """
    command = f'strace -p {pid} -o {output_file}'  # Command to start strace on the specific PID
    process = subprocess.Popen([ADB_PATH, 'shell', command])  # Run the strace command on the Android device
    return process  # Return the strace process for later termination

def stop_strace(process):
    """
    Stops the strace process.
    Terminates strace properly to avoid incomplete or corrupted output.
    """
    subprocess.run([ADB_PATH, 'shell', 'pkill', 'strace'])  # Kill the strace process on the device
    process.terminate()  # Terminate the local process tracking strace
    process.wait()  # Wait for the process to fully terminate

def pull_strace_output(output_file_on_device, local_output_file):
    """
    Pulls the strace output file from the device to the local machine.
    Important for analyzing system calls captured during monitoring.
    """
    subprocess.run([ADB_PATH, 'pull', output_file_on_device, local_output_file])  # Pull the strace output from the device
    print(f'Strace output saved to {local_output_file}')  # Inform the user that the strace output is saved

def system_calls_recon_main():
    pid = get_app_pid(PACKAGE_NAME)  # Get the PID of the target app
    if not pid:
        return  # If the app is not running, stop the process

    print(f'Starting strace on PID {pid}...')
    strace_process = start_strace(pid, STRACE_OUTPUT_ON_DEVICE)  # Start system call monitoring (strace)
    try:
        print(f'Monitoring system calls for {DURATION} seconds...')
        time.sleep(DURATION)  # Monitor for the specified duration (60 seconds)
    finally:
        print('Stopping strace...')
        stop_strace(strace_process)  # Stop the system call monitoring process
        print('Pulling strace output to local machine...')
        pull_strace_output(STRACE_OUTPUT_ON_DEVICE, STRACE_LOCAL_OUTPUT)  # Pull the output to local storage
        print('System calls monitoring completed.')
        subprocess.run([ADB_PATH, 'shell', f'rm {STRACE_OUTPUT_ON_DEVICE}'])  # Clean up the strace output on the device

    #TODO: Reference Dictionary     
    # Store strace output path as a feature
    #dynamic_features['system_calls_file'] = STRACE_LOCAL_OUTPUT
    
# STAGE 3: FILESYSTEM RECON
# 'inotifywait' monitors file system activities
# Is the malware modifying, creating, deleting files
# Popen is a function that allows to start new process with inotifywait command
def start_inotifywait(directory_to_monitor, output_file):
    """
    Starts inotifywait on the device to monitor the specified directory for file changes.
    Monitors file system activities to detect suspicious behavior, such as file modifications or deletions.
    """
    command = f'inotifywait -m -r {directory_to_monitor}'  # Command to start inotifywait to monitor file system changes
    with open(output_file, 'w') as outfile: # indicates that the file is opened in write mode (w)
        process = subprocess.Popen([ADB_PATH, 'shell', command], stdout=outfile, stderr=subprocess.STDOUT)  # Run the command and save output
    return process  # Return the inotifywait process for later termination

def stop_inotifywait(process):
    """
    Stops the inotifywait process.
    Properly stops file system monitoring and ensures data integrity.
    """
    subprocess.run([ADB_PATH, 'shell', 'pkill', 'inotifywait'])  # Kill the inotifywait process on the device
    process.terminate()  # Terminate the local process tracking file changes
    process.wait()  # Wait for the process to fully stop

def filesystem_recon_main():
    print(f'Starting file system monitoring on {DIRECTORY_TO_MONITOR}...')
    inotify_process = start_inotifywait(DIRECTORY_TO_MONITOR, FILESYSTEM_OUTPUT_FILE)  # Start file system monitoring
    try:
        print(f'Monitoring file system for {DURATION} seconds...')
        time.sleep(DURATION)  # Monitor for the specified duration (60 seconds)
    finally:
        print('Stopping file system monitoring...')
        stop_inotifywait(inotify_process)  # Stop the file system monitoring process
        print(f'File system changes saved to {FILESYSTEM_OUTPUT_FILE}')

    #TODO: Reference Dictionary
    #dynamic_features['file_system_changes_file'] = FILESYSTEM_OUTPUT_FILE  # Store file system change log path

# STAGE 4: NETWORK CAPTURE RECON
# tcpdump a tool for capturing network traffic
def check_tcpdump_on_device():
    """
    Checks if tcpdump is present on the device.
    If tcpdump is not found, this function pushes the binary to the device.
    """
    result = subprocess.run([ADB_PATH, 'shell', 'which tcpdump'], capture_output=True, text=True)  # Check if tcpdump is installed
    if 'tcpdump' in result.stdout:
        print('tcpdump is already installed on the device.')  # Inform if tcpdump is already present
    else:
        print('tcpdump not found on device. Attempting to install...')
        tcpdump_binary = 'tcpdump'  # Path to the tcpdump binary (for Android)
        subprocess.run([ADB_PATH, 'push', tcpdump_binary, '/data/local/tmp/tcpdump'])  # Push tcpdump to the device
        subprocess.run([ADB_PATH, 'shell', 'chmod 755 /data/local/tmp/tcpdump'])  # Set executable permissions
        print('tcpdump installed on the device.')

def start_tcpdump():
    """
    Starts tcpdump on the device to capture network traffic.
    Important for analyzing network communication patterns, including possible C2 communications.
    """
    tcpdump_command = f"/data/local/tmp/tcpdump -i any -p -s 0 -w {TCPDUMP_DEVICE_PCAP_FILE}"  # Command to start tcpdump
    process = subprocess.Popen([ADB_PATH, 'shell', tcpdump_command])  # Run the tcpdump command on the device
    return process, TCPDUMP_DEVICE_PCAP_FILE  # Return the tcpdump process and the path to the pcap file on the device

def stop_tcpdump(process):
    """
    Stops tcpdump on the device.
    Properly terminates the tcpdump process to avoid corruption of captured data.
    """
    subprocess.run([ADB_PATH, 'shell', 'pkill', 'tcpdump'])  # Kill the tcpdump process on the Android device
    process.terminate()  # Terminate the local process tracking tcpdump
    process.wait()  # Wait for the process to fully stop

def pull_pcap_file(pcap_file_on_device, local_pcap_file):
    """
    Pulls the pcap file from the device to the local machine.
    Important for analyzing network traffic with tools like Wireshark.
    """
    subprocess.run([ADB_PATH, 'pull', pcap_file_on_device, local_pcap_file])  # Pull the pcap file from the device
    print(f'PCAP file saved to {local_pcap_file}')  # Inform the user that the PCAP file has been saved locally

def network_capture_recon_main():
    """
    Main function for capturing network traffic using tcpdump.
    Checks if tcpdump is present on the device, starts the capture, and pulls the result.
    """
    check_tcpdump_on_device()  # Check if tcpdump is installed or install it if missing
    print('Starting tcpdump on device...')
    tcpdump_process, pcap_file_on_device = start_tcpdump()  # Start tcpdump to capture network traffic
    try:
        print(f'Capturing network traffic for {DURATION} seconds...')
        time.sleep(DURATION)  # Capture network traffic for the set duration
    finally:
        print('Stopping tcpdump on device...')
        stop_tcpdump(tcpdump_process)  # Stop the tcpdump process
        print('Pulling pcap file to local machine...')
        pull_pcap_file(pcap_file_on_device, TCPDUMP_LOCAL_PCAP_FILE)  # Pull the pcap file from the device to the local machine
        print('Network traffic capture completed.')
        subprocess.run([ADB_PATH, 'shell', f'rm {pcap_file_on_device}'])  # Clean up by removing the pcap file from the device

    #TODO: Reference Dictionary
    #dynamic_features['network_traffic_file'] = TCPDUMP_LOCAL_PCAP_FILE  # Store network traffic pcap file path


# Combined main function to run all processes in sequence
if __name__ == '__main__':
    print("Starting Dynamic Analysis Framework...")
    
    # Log collection process (Logcat)
    log_collecting_main()
    
    # System call monitoring process (strace)
    system_calls_recon_main()
    
    # File system monitoring process (inotifywait)
    filesystem_recon_main()
    
    # Network traffic capture process (tcpdump)
    network_capture_recon_main()

    print("Dynamic Analysis Completed!")

