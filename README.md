# white rAbbIt - Hybrid Android Malware Analysis Tool
white rAbbIT is an automated Android malware analysis tool that combines static and dynamic analysis techniques with advanced machine learning to classify apps with precision. Designed specifically for reverse engineers and red team specialists, the tool provides explainable insights to enhance understanding and streamline efficient reporting.


---

## Features

### Static Analysis
- **Feature Extraction Status**: Displays progress and status of feature extraction processes.
- **Feature Summary**: Summarizes extracted features from APK files (API calls, permissions, intents, and command signatures). 
- **Classification**: Determines the classification of the APK using our supervised learning ML model.
  
### Dynamic Analysis
- **Feature Extraction Status**: Displays progress and status of feature extraction processes.
- **Feature Summary**: Summarizes extracted features from APK runtime traffic statistics (ip.src,ip.dst,tcp.srcport,tcp.dstport,http.request.uri,and frame.len). 
- **Classification**: Determines the classification of the APK using LLM (gpt-3.5-turbo).

### Model Insights
- **Model Explanation Button**: Provides insights into the machine learning model's decision-making process using explainable AI techniques.
- **Model Insights Display**:  Displays explanations for classification results using explainable AI (e.g., feature importance or decision rationale).

### Log Management
- **Clear Logs Button**: Clears the logs display area.
- **Save Logs Button**: Allows users to save captured logs and results to a file.

### Hybrid Classification Results
-  **Determine Overall Classification Button**: Leverages both static and dynamic models to deliver a more accurate malware classification, incorporating both model results to enhance reliability
-  **Hybrid Classification Results Display**: Shows the overall classification, combined confidence score, dynamic/static weights, distance from the decission boundary, static classification, static confidence, dynamic classification, and dynamic confidence.

### Report Generation
- Automatically generates comprehensive analysis reports for users.
---

### Operating System:
- Ubuntu 24.04.1 LTS or later

## Prerequisites

1. **Python**: Ensure Python 3.12.3 is installed.
2. **Python Modules**: Install the required Python modules using the provided `requirements.txt` file.
3. **OpenAI API Key**: Obtain an OpenAI API key and ensure it has access to the `gpt-3.5-turbo` model.
4. **Environment Variable**: Save the API key as an environment variable named `OPENAI_API_KEY`.
5. **Android Studio**: Download and install [Android Studio](https://developer.android.com/studio).
6. **ADB (Android Debug Bridge)** and **AVD Manager**: Verify these tools are accessible from your system's PATH.
   ```bash
   adb version
   emulator -version
   ```
4. **TCPDump**: Obtain a compatible `tcpdump` binary for Android.

---

## Setting Up the Android Emulator

### 1. Install Android Studio and Required Tools

1. Download and install [Android Studio](https://developer.android.com/studio).
2. Ensure the following tools are installed:
   - **ADB (Android Debug Bridge)**
   - **AVD Manager**
3. Verify the installations:
   ```bash
   adb version
   emulator -version
   ```

### 2. Create and Configure the Emulator

1. Open **AVD Manager** from Android Studio.
2. Create a new virtual device with the following configuration:
   - **Device**: Pixel 2
   - **System Image**: Android 8.1 Oreo (API Level 27) - x86_64
3. Click **Show Advanced Settings** and set:
   - **RAM**: 2048 MB
   - **VM Heap**: 512 MB
   - Enable **"Device Frame"**.
4. Save the configuration and launch the emulator to verify it works.

### 3. Root the Emulator

1. Launch the emulator:
   ```bash
   emulator -avd Pixel_2_API_27
   ```
2. Verify root access:
   ```bash
   adb shell
   su
   ```
   - If the `su` command works without issues, the emulator is rooted.

### 4. Install and Configure `tcpdump`

1. **Download `tcpdump`**:
   - Obtain the x86_64 `tcpdump` binary from the [tcpdump-group](https://github.com/the-tcpdump-group) or use a precompiled binary for Android.
2. Push the binary to the emulator:
   ```bash
   adb push tcpdump /data/local/tmp/
   ```
3. Set the correct permissions:
   ```bash
   adb shell
   chmod 755 /data/local/tmp/tcpdump
   ```
4. Verify installation:
   ```bash
   adb shell /data/local/tmp/tcpdump --version
   ```

### 5. Save a Snapshot with `tcpdump` Installed

1. Launch the emulator:
   ```bash
   emulator -avd Pixel_2_API_27
   ```
2. Verify `tcpdump` is in place and functional:
   ```bash
   adb shell /data/local/tmp/tcpdump --version
   ```
3. Save the emulator state as a snapshot:
   ```bash
   adb emu avd snapshot save snap_2024_11-18_12-00-24
   ```
4. Confirm the snapshot was saved:
   ```bash
   adb emu avd snapshot list
   ```

### 6. Test Emulator and Snapshot

1. Launch the emulator with the saved snapshot:
   ```bash
   emulator -avd Pixel_2_API_27 -snapshot snap_2024_11-18_12-00-24
   ```
2. Confirm `tcpdump` is accessible:
   ```bash
   adb shell /data/local/tmp/tcpdump --version
   ```

---

## Usage
### Model Building Notebook

The complete process for building the Static machine learning model is documented in the Jupyter Notebook located at:

```
model/static/End to End Model Building
```

This notebook contains:
- Data cleaning
- Feature engineering 
- Data preprocessing steps
- Modeling and evaluation
- Global interpretability

### Installing Dependencies

1. Create and activate a virtual environment (optional but recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  
   ```

2. Install the required Python modules:
   ```bash
   pip install -r requirements.txt
   ```
## To Run

1. Launch the white rAbbIt application (`white_rAbbIt_gui.py`)
2. Load the APK file for analysis.
3. Select either Static Analysis or Dynamic Analysis and monitor the feature extraction and logs in the interface.
4. Review model insights and analysis results.
5. Select the other analysis type and monitor the feature extraction and logs in the interface.
6. Review model insights and analysis results.
7. Determine the overall classification 
8. Generate th Hybrid Analysis report (saved in working dir).

## ISO

[white rAbbIt ISO](https://drive.google.com/drive/u/1/folders/1koQsMzsb46wEjqlULfr4YeLGg-VG6N9i)

### Demo 
![demo.mp4](https://github.com/C-Tindilia/Capstone_white-rAbbIt/blob/main/demo.mp4?raw=true)
---


