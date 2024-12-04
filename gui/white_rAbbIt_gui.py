#######################################################################################
#                                  white rAbbIt GUI                                   #                       
####################################################################################### 
'''
A graphical user interface (GUI) for the white rAbbIt Hybrid Android Malware Analysis Tool.

    This class defines the main window of the malware analysis application, including widgets, layouts, 
    and interactions. It provides an intuitive interface for users to perform static and dynamic 
    analysis of APK files, view results, and generate detailed reports.

   Features:
        - **Select APK**: Allows users to select APK files for analysis through a file selection dialog.
        - **Static Analysis**: Performs static analysis to extract features such as API calls, permissions,
          intents, and command signatures from the APK file.
        - **Feature Display**: Displays a summary of extracted features from APK files, categorized into 
          API calls, permissions, intents,command signatures and traffic statistics.
        - **Dynamic Analysis**: Initiates a sandboxed dynamic analysis process to monitor runtime behavior 
          to include capturing network traffic.
        - **Log Management**: Enables users to view logs in real-time, save them to a file for future reference, 
          and clear the log display area when needed.
        - **Model Insights**: Displays explanations for classification results using explainable AI (e.g., 
          feature importance or decision rationale).
        - **Hybrid Classification Results**: Combines results from static and dynamic analysis to provide 
          a comprehensive classification of the APK (benign or malicious).
        - **Report Generation**: Generates and saves detailed reports of the analysis results, 
          including extracted features, classification outcomes, and supporting evidence.
'''
import sys
import os
#import subprocess
#import threading
import numpy as np
from PyQt5.QtCore import Qt, pyqtSlot, QThread
from PyQt5.QtGui import QPixmap, QFont
from PyQt5.QtWidgets import (QApplication, QMainWindow, QLabel, QPushButton, QTextEdit, QProgressBar,
                             QFileDialog, QGridLayout, QWidget)
import joblib
from static_feature_extraction_thread import FeatureExtractionWorker
from static_analysis_XAI import static_XAI
from dynamic_feature_extraction_thread import EmulatorThread 
from extracting_formatting_tokenizing_pcap_thread import PcapDataProcessor
from dynamic_analysis_and_XAI import classify_apk_network_traffic
from report_generation import generate_report

#######################################################################################
#                           Framework for Building App UI                             #                       
####################################################################################### 

#Defined the whiterAbbIt class. QMainWindow class provides a main application window.
class whiterAbbIt(QMainWindow):
    def __init__(self):
        super().__init__()

        # Set window properties- Title and size (position and dimensions) of the main window.
        self.setWindowTitle("White rAbbIt - Hybrid Android Malware Analysis Tool")
        self.setGeometry(100, 100, 1200, 800)

        # Appled dark theme and custom styles
        self.setStyleSheet("""
            QMainWindow {
                background-color: #2D2D30;
                color: white;
            }
            QLabel {
                color: #FFFFFF;
            }
            QPushButton {
                background-color: #3E3E42;
                color: #FFFFFF;
                border-radius: 5px;
                padding: 10px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #505050;
            }
            QTextEdit {
                background-color: #1E1E1E;
                color: #FFFFFF;
                border: 1px solid #3E3E42;
            }
            QProgressBar {
                background-color: #1E1E1E;
                color: #FFFFFF;
                border-radius: 5px;
            }
            QSplitter::handle {
                background-color: #3E3E42;
            }
        """)

        # Created grid layout of organizing widgets within main layout
        self.main_layout = QGridLayout()

        # Centered Application Name "white rAbbIt" and Description
        self.title_label = QLabel(self)
        formatted_text = 'white r<b><span style="color:#FF0000;">A</span></b>bb<span style="color:#FF0000;">I</span>t'
        self.title_label.setText(formatted_text)
        self.title_label.setFont(QFont('Arial', 24, QFont.Bold))
        self.title_label.setAlignment(Qt.AlignCenter)
        self.main_layout.addWidget(self.title_label, 0, 1, 1, 3)

        # Breif description of the tool below the tiles, centered.
        self.description_label = QLabel("A Hybrid Android Malware Analysis Tool")
        self.description_label.setFont(QFont('Arial', 14))
        self.description_label.setAlignment(Qt.AlignCenter)
        self.main_layout.addWidget(self.description_label, 1, 1, 1, 3)

        # white rAbbIt logo in the top-left corner and scaled to extend vertically across 3 rows
        self.main_logo = QLabel(self)
        self.main_logo.setPixmap(QPixmap("images/Designer(3).jpeg").scaled(200, 400, Qt.KeepAspectRatio))
        self.main_layout.addWidget(self.main_logo, 0, 0, 3, 1)  # Extend image vertically across 3 rows

        # Created "Select APK" button. Connects its click event to select_apk method
        self.select_button = QPushButton("Select APK")
        self.select_button.clicked.connect(self.select_apk)
        self.main_layout.addWidget(self.select_button, 2, 0)

        # Created "Static Analysis" button (red). Connects its click event to analyze_apk method 
        self.static_analysis_button = QPushButton("Static Analysis")
        self.static_analysis_button.setStyleSheet("""
            QPushButton {
                background-color: #D32F2F;
                color: #FFFFFF;
                border-radius: 5px;
                padding: 10px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #F44336;
            }
        """)
        self.static_analysis_button.clicked.connect(self.analyze_apk)
        self.main_layout.addWidget(self.static_analysis_button, 2, 1, 1, 3)

        # Save Logs Button
        self.save_logs_button = QPushButton("Save Logs")
        self.save_logs_button.clicked.connect(self.save_logs)
        self.main_layout.addWidget(self.save_logs_button, 3, 0)

        # Clear Logs Button
        self.clear_logs_button = QPushButton("Clear Logs")
        self.clear_logs_button.clicked.connect(self.clear_logs)
        self.main_layout.addWidget(self.clear_logs_button, 4, 0)

        # Model Explanation Button. Connects its click event to show_model_explanation method
        self.model_insights_label = QLabel("XAI Simplified Results")
        self.model_explanation_button = QPushButton("Model Explanation")
        self.model_explanation_button.clicked.connect(self.show_model_explanation)
        self.main_layout.addWidget(self.model_explanation_button, 5, 0)

        # Determine Overall Classification Button. Connects its click event to calculate_overall_score method
        self.hybrid_class_button = QPushButton("Determine Overall Classification")
        self.hybrid_class_button.clicked.connect(self.calculate_overall_score)
        self.main_layout.addWidget(self.hybrid_class_button, 6, 0)
        
        # Generate Report Button. Connects its click event to generate_report method
        self.report_button = QPushButton("Generate Report")
        self.report_button.clicked.connect(self.generate_analysis_report)
        self.main_layout.addWidget(self.report_button, 7, 0)

        # Static Feature Extraction Status. Initializes the progress bar's value and maximum
        self.feature_extraction_status_label = QLabel("Static Feature Extraction Status")
        self.feature_extraction_status = QProgressBar(self)
        self.feature_extraction_status.setValue(0)
        self.feature_extraction_status.setMaximum(100)
        self.thread = None
        self.main_layout.addWidget(self.feature_extraction_status_label, 3, 1)
        self.main_layout.addWidget(self.feature_extraction_status, 4, 1)

        # Static Malware analysis gauge. Initializes the progress bar's value and maximum
        self.analysis_gauge_label = QLabel("Static Malware Analysis Progress")
        self.analysis_gauge = QProgressBar(self)
        self.analysis_gauge.setValue(0)
        self.analysis_gauge.setMaximum(100)
        self.main_layout.addWidget(self.analysis_gauge_label, 3, 2)
        self.main_layout.addWidget(self.analysis_gauge, 4, 2)
        
        # Static results gauge (confidence score)
        self.results_gauge_label = QLabel("Static Analysis Confidence Score")
        self.results_gauge = QProgressBar(self)
        self.results_gauge.setValue(0)
        self.results_gauge.setMaximum(100)
        self.main_layout.addWidget(self.results_gauge_label, 3, 3)
        self.main_layout.addWidget(self.results_gauge, 4, 3)

        # Created "Dynamic Analysis" button (red). Connects its click event to start_emulator method 
        self.dynamic_analysis_button = QPushButton("Dynamic Analysis")
        self.dynamic_analysis_button.setStyleSheet("""
            QPushButton {
                background-color: #D32F2F;
                color: #FFFFFF;
                border-radius: 5px;
                padding: 10px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #F44336;
            }
        """)
        self.dynamic_analysis_button.clicked.connect(self.start_dynamic_analysis)
        self.main_layout.addWidget(self.dynamic_analysis_button, 5, 1, 1, 3)
        
        # Dynamic Feature Extraction Status. Initializes the progress bar's value and maximum
        self.dynamic_feature_extraction_status_label = QLabel("Dynamic Feature Extraction Status")
        self.dynamic_feature_extraction_status = QProgressBar(self)
        self.dynamic_feature_extraction_status.setValue(0)
        self.dynamic_feature_extraction_status.setMaximum(100)
        self.thread = None
        self.main_layout.addWidget(self.dynamic_feature_extraction_status_label, 6, 1)
        self.main_layout.addWidget(self.dynamic_feature_extraction_status, 7, 1)

        # Dynamic Malware analysis gauge. Initializes the progress bar's value and maximum
        self.dynamic_analysis_gauge_label = QLabel("Dynamic Malware Analysis Progress")
        self.dynamic_analysis_gauge = QProgressBar(self)
        self.dynamic_analysis_gauge.setValue(0)
        self.dynamic_analysis_gauge.setMaximum(100)
        self.main_layout.addWidget(self.dynamic_analysis_gauge_label, 6, 2)
        self.main_layout.addWidget(self.dynamic_analysis_gauge, 7, 2)

        # Dynamic results gauge (confidence score)
        self.dynamic_results_gauge_label = QLabel("Dynamic Analysis Confidence Score")
        self.dynamic_results_gauge = QProgressBar(self)
        self.dynamic_results_gauge.setValue(0)
        self.dynamic_results_gauge.setMaximum(100)
        self.main_layout.addWidget(self.dynamic_results_gauge_label, 6, 3)
        self.main_layout.addWidget(self.dynamic_results_gauge, 7, 3)

        # Application Logs Display Area
        self.logs_display_label = QLabel("Application Logs")
        self.logs_display = QTextEdit(self)
        self.logs_display.setReadOnly(True)
        self.main_layout.addWidget(self.logs_display_label, 8, 1)
        self.main_layout.addWidget(self.logs_display, 9, 1, 7, 1)

        # Feature Summary Display Area 
        self.feature_summary_label = QLabel("Extracted Feature Summary")
        self.feature_summary_display = QTextEdit(self)
        self.feature_summary_display.setReadOnly(True)
        self.main_layout.addWidget(self.feature_summary_label, 8, 2)
        self.main_layout.addWidget(self.feature_summary_display, 9, 2, 7, 1)

        # XAI Display Area 
        self.model_insights_display = QTextEdit(self)
        self.model_insights_display.setReadOnly(True)
        self.main_layout.addWidget(self.model_insights_label, 8, 3)
        self.main_layout.addWidget(self.model_insights_display,  9, 3, 1, 1)

        # Overall Determination
        self.overall_class_label = QLabel("Hybrid Classification Results")
        self.overall_class_display = QTextEdit(self)
        self.overall_class_display.setReadOnly(True)
        self.main_layout.addWidget(self.overall_class_label, 10, 3)
        self.main_layout.addWidget(self.overall_class_display, 11, 3, 5, 1)

        # Create central widget and set layout
        container = QWidget()
        container.setLayout(self.main_layout)
        self.setCentralWidget(container)

    #######################################################################################
    #                           ML and EMU Verification and Config                        #                       
    ####################################################################################### 

        # Load the static trained model
        self.load_model()

        # Check for openai api key
        self.check_for_openai_api_key()

        # Initialize EmulatorThread
        self.apk_file = None
        self.worker_thread = None
        self.emulator_thread = None
        
        # Emulator Directory 
        self.emulator_dir = "Android/Sdk/emulator"
        # Start emulator, load from snapshot (initilaized with tcpdump installed)
        self.emulator_command = "emulator -avd Pixel_2_API_27 -snapshot snap_2024-11-18_12-00-24"
        # adb command and path
        self.adb_command = ["adb", "devices"]
        self.adb_path = "adb"

    def load_model(self):
        # Load the pre-trained model from the joblib file 
        try:
            self.static_trained_model = joblib.load ("models/static/trained model/static_trained_model.joblib")
            self.logs_display.append ("Static Model Loaded Successfully")
        except Exception as e:
            self.logs_display.append(f"Error loading model {e}")
    
    def check_for_openai_api_key(self):
        try:
            if 'OPENAI_API_KEY' in os.environ:
                self.logs_display.append("Dynamic Model Access Permitted.")
            else:
                self.logs_display.append("Dynamic Model Access Denied.")
        except Exception as e:
            self.logs_display.append(f"Error loading model {e}")

    #######################################################################################
    #                                  Select APK                                         #                       
    #######################################################################################

    @pyqtSlot()
    def select_apk(self):
        file_dialog = QFileDialog(self)
        file_dialog.setFileMode(QFileDialog.ExistingFile)

        apk_file, _ = file_dialog.getOpenFileName(self, "Select APK File", "", "APK Files (*.apk)")
        self.apk_file = apk_file
        # Update log display with selected APK info
        self.logs_display.append(f"Selected APK: {os.path.basename(apk_file)}")
        
        # Restart guages when new APK is selected 
        self.feature_extraction_status.setValue(0)
        self.analysis_gauge.setValue(0)
        self.results_gauge.setValue(0)

        # Remove the Android logo when a new APK is selected if present
        if hasattr(self, 'logo') and self.logo:
            self.logo.clear()

    #######################################################################################
    #                                  Static Analysis & XAI                              #                       
    #######################################################################################

    @pyqtSlot()
    def analyze_apk(self):
        '''
        Initiates the analysis process for the selected APK file.

        This method extracts features from the selected APK file to support static analysis. It creates a 
        separate thread for the feature extraction process to keep the GUI responsive. The method updates 
        the logs display with progress or error messages and connects relevant signals for thread management.
        '''
        try: 
            if self.apk_file:
                self.logs_display.append("Extracting features in support of static analysis...")

                # Create a QThread for feature extraction
                self.thread = QThread()
                self.worker = FeatureExtractionWorker(self.apk_file)

                # Move the worker to the thread
                self.worker.moveToThread(self.thread)

                # Connect signals and slots
                self.thread.started.connect(self.worker.run)
                self.worker.progress.connect(self.update_progress_bar)
                self.worker.finished.connect(self.feature_extraction_finished)
                self.worker.error.connect(self.feature_extraction_error)

                # Start the thread
                self.thread.start()
            else:
                self.logs_display.append("Error: No APK file selected. Please select an APK file first.")
        except:
            self.logs_display.append(f"Error: No APK file selected. Please select an APK file first.")

    def update_progress_bar(self, progress):
        self.feature_extraction_status.setValue(progress)

    def feature_extraction_finished(self, feature_presence_df, app_name):
        #Create a dataframe of all features whose value is '1' (present)
        df_filtered = feature_presence_df.loc[:, feature_presence_df.eq(1).any()]
        # Display app name discovered in AndroidManifest.xml
        self.logs_display.append(f"App Name: {app_name}")
        # Display the count of extracted features 
        self.logs_display.append(f"Features present: {str(df_filtered.shape[1])}/{str(feature_presence_df.shape[1])}")
        # Display the extracted features 
        self.display_extracted_features(df_filtered)
        self.static_features = df_filtered
               
        # Pass the DataFrame to run_static_analysis for predictions
        self.run_static_analysis(feature_presence_df)
        # Stop the thread
        self.thread.quit()

    def feature_extraction_error(self, error_message):
        self.logs_display.append(f"Error during feature extraction: {error_message}")
        # Stop the thread
        self.thread.quit()
    
    def display_extracted_features(self, columns):
        for col in columns:
            self.feature_summary_display.append(col)
    

    def run_static_analysis(self, feature_presence_df):
        '''
        Performs static analysis on the provided feature presence DataFrame.

        This method uses the pre-trained static machine learning model to classify the APK file as 
        benign or malicious based on the provided feature presence DataFrame. It logs progress, 
        updates the GUI with results, and generates explainable AI (XAI) insights to support 
        classification decisions.
        '''
        if self.static_trained_model is not None:
            
            try:
                self.logs_display.append("Running static analysis on features...")
                
                #Classify APK file
                self.static_prediction = self.static_trained_model.predict(feature_presence_df)
                # Predicted probaboloties of the respective class for the input sample 
                # Computed to be passed to XAI function to determine connfidence level
                self.static_predict_probability = self.static_trained_model.predict_proba(feature_presence_df)
                
                # Update progress bar after analysis 
                self.analysis_gauge.setValue(100)
                self.logs_display.append("Static analysis completed.")


                if self.static_prediction[0] == 0:
                    self.logs_display.append(f"Static Analysis Classification Result: Benign")
                    self.logo = QLabel(self)
                    self.logo.setPixmap(QPixmap("images/Designer(6).jpeg").scaled(200, 400, Qt.KeepAspectRatio))
                    self.main_layout.addWidget(self.logo, 8, 0, 6, 1)  # Extend image vertically across 6 rows

                elif self.static_prediction[0] == 1:
                    self.logs_display.append(f"Static Analysis Classification Result: Malicious")
                    self.logo = QLabel(self)
                    self.logo.setPixmap(QPixmap("images/Designer(5).jpeg").scaled(200, 400, Qt.KeepAspectRatio))
                    self.main_layout.addWidget(self.logo, 8, 0, 6, 1)  # Extend image vertically across 6 rows

            except Exception as e:
                self.logs_display.append(f"Error during prediction: {e}")
        else:
            self.logs_display.append("Model not loaded, cannot make predictions")
        
        # Generate XAI explanation
        static_XAI(self, feature_presence_df)
        
        # Update analysis confidence score gauge
        self.results_gauge.setValue(int(np.max(self.static_predict_probability[0])*100))


    #######################################################################################
    #                                 Show XAI Explanation                                #                       
    #######################################################################################
          
    def show_model_explanation(self):
        # Initialize flags to track whether explanations have been displayed
        if not hasattr(self, 'explanation_displayed'):
            self.explanation_displayed = {
                'static': False,
                'dynamic': False
            }

        # Check if lime_explanation exists and display it
        if hasattr(self, 'lime_explanation') and not self.explanation_displayed['static']:
            self.model_insights_display.append("---------Static Analysis---------\n")
            self.model_insights_display.append(f"Predicted Class: {np.argmax(self.static_predict_probability[0])}")
            self.model_insights_display.append(f"Predicted Probability: {np.max(self.static_predict_probability[0]):.2f}")

            # Display top 10 features
            self.model_insights_display.append("Top 10 Features:")
            for feature, weight in self.lime_explanation.as_list():
                self.model_insights_display.append(f"{feature}: {weight:.2f}")
            
            # Mark static explanation as displayed
            self.explanation_displayed['static'] = True

        # If dynamic_explanation exists, append it to the model insights display
        if hasattr(self, 'dynamic_explanation') and not self.explanation_displayed['dynamic']:
            self.model_insights_display.append("---------Dynamic Analysis---------")
            self.model_insights_display.append(self.dynamic_explanation)
            
            # Mark dynamic explanation as displayed
            self.explanation_displayed['dynamic'] = True

        # If neither explanation exists, show a message
        if not (hasattr(self, 'lime_explanation') or hasattr(self, 'dynamic_explanation')):
            self.model_insights_display.append("No explanation available. Run static analysis or dynamic analysis first.")
    

    #######################################################################################
    #                                  Dynamic Analysis & XAI                             #                       
    #######################################################################################
    '''
    Workflow:
            - The emulator is launched, and the APK is installed.
            - Monkey testing is conducted to simulate user interactions.
            - Logs are captured, processed, and analyzed for dynamic feature extraction.
            - The extracted features are classified using a dynamic classifier, with confidence scores 
            displayed along with explainable AI insights.    
    '''
    
    @pyqtSlot()
    def start_dynamic_analysis(self):
        '''
        Initiates the dynamic analysis process by launching the emulator, installing the APK, 
        and handling subsequent tasks such as log extraction and classification.

        This method performs the following:
            1. Validates if an APK file is selected.
            2. Creates an `EmulatorThread` to manage emulator initialization and APK installation.
            3. Connects various signals emitted by the emulator thread to corresponding slots for:
                - Notifying when the emulator starts or is ready.
                - Indicating successful APK installation.
                - Handling errors in the dynamic analysis process.
                - Simulating user interactions via Monkey testing.
                - Updating logs from the emulator.
                - Processing pcap logs and extracting features for dynamic analysis.
            4. Starts the emulator thread to begin the dynamic analysis workflow.  
        '''
        try:
            if not self.apk_file:
                self.logs_display.append("Error: No APK file selected.")
                return
            
            # Create EmulatorThread to handle emulator and APK installation
            self.emulator_thread = EmulatorThread(
                self.emulator_dir, self.emulator_command, self.adb_command, self.apk_file, self.adb_path, 
            )

            # Connect signals after the thread has been instantiated
            self.emulator_thread.emulator_started.connect(self.on_emulator_started)
            self.emulator_thread.emulator_ready.connect(self.on_emulator_ready)
            self.emulator_thread.apk_installed.connect(self.on_apk_installed)
            self.emulator_thread.error.connect(self.on_error)
            self.emulator_thread.monkey_test.connect(self.simulated_user_interactions)
            self.emulator_thread.log_signal.connect(self.update_logs_display)  
            self.emulator_thread.pcap_loaded_to_host.connect(self.process_logs)

            # Start the emulator thread
            self.emulator_thread.start()

        except Exception as e:
            self.logs_display.append(f"Error starting dynamic analysis: {e}")
            print(f"Error: {e}")
            

    def on_emulator_started(self):
        """Update GUI when the emulator starts."""
        self.logs_display.append("Emulator started.")
    
    def on_emulator_ready(self):
        """Update GUI when the emulator is ready."""
        self.logs_display.append("Emulator is ready.")

    @pyqtSlot()
    def on_apk_installed(self):
        """Update GUI when APK is installed."""
        self.logs_display.append("APK installed successfully.")

    @pyqtSlot()
    def simulated_user_interactions(self):
        """Upadate GUI when user interation is simulated via monkey"""
        self.logs_display.append("Monkey simulation completed.")

    @pyqtSlot(str)
    def on_error(self, error_msg):
        """Handle errors in the emulator or APK installation process."""
        self.logs_display.append(f"Error: {error_msg}")
    
    @pyqtSlot(str)
    def update_logs_display(self, log_message):
        """Update the logs display with messages from the emulator thread."""
        self.logs_display.append(log_message)

    @pyqtSlot(str)
    def process_logs(self, pcap_file_location_on_host):
        self.update_dynamic_feature_extraction_gauge()
        self.worker = PcapDataProcessor(pcap_file_location_on_host)
        # Connect the signal to a slot that will update the UI with the results
        self.worker.processed_data_signal.connect(self.dynamic_extracted_features_display)
        
        # Start the worker thread
        self.worker.start()
        
    @pyqtSlot(str)
    def dynamic_extracted_features_display(self, log_str):
        print ("Logs received from worker thread.")
        self.feature_summary_display.append(log_str)
        self.logs_display.append("Log extraction and formatting complete.")
        self.logs_display.append("Dynamic classification and XAI starting...")
        self.dynamic_clasification_and_XAI(log_str)
        self.dynamic_features = log_str

    
    def dynamic_clasification_and_XAI(self, log_str):
        self.dynamic_classification, self.dynamic_confidence_score, self.dynamic_explanation = classify_apk_network_traffic(log_str)
        self.logs_display.append("Dynamic classification and XAI completed.")
        self.dynamic_analysis_gauge.setValue(100)
        if self.dynamic_classification == 0:
                self.logs_display.append(f"Dynamic Analysis Classification Result: Benign")
                self.logo = QLabel(self)
                self.logo.setPixmap(QPixmap("images/Designer(6).jpeg").scaled(200, 400, Qt.KeepAspectRatio))
                self.main_layout.addWidget(self.logo, 8, 0, 6, 1)  # Extend image vertically across 6 rows

        elif self.dynamic_classification == 1:
            self.logs_display.append(f"Dynamic Analysis Classification Result: Malicious")
            self.logo = QLabel(self)
            self.logo.setPixmap(QPixmap("images/Designer(5).jpeg").scaled(200, 400, Qt.KeepAspectRatio))
            self.main_layout.addWidget(self.logo, 8, 0, 6, 1)  # Extend image vertically across 6 rows

        if self.dynamic_confidence_score != 0:
            self.dynamic_results_gauge.setValue(int(self.dynamic_confidence_score * 100))
        else: 
            self.dynamic_results_gauge.setValue(0)
            self.logs_display.append(f"The dynamic classifier is unsure. Rerun dynamic analysis and interact with the emulator to generate more data.")
            
    def update_dynamic_feature_extraction_gauge(self):
        self.dynamic_feature_extraction_status.setValue(100)


    #######################################################################################
    #                                  Hybrid Classification                              #                       
    #######################################################################################
    
    @pyqtSlot()
    def calculate_overall_score(self):
        """Calculate and display the overall classification score."""
        try:
            # Ensure both static and dynamic analyses are complete
            if not hasattr(self, 'static_prediction') or not hasattr(self, 'dynamic_classification'):
                self.logs_display.append("Both static and dynamic analyses must be completed to calculate the overall score.")
                return
            
            # Get the classification (1 for malicious, 0 for benign) from each model
            static_classification = self.static_prediction[0]  
            dynamic_classification = self.dynamic_classification  
            
            # Get the confidence scores for each model 
            P_static = self.static_predict_probability[0][1]  # Confidence score for malicious

            P_dynamic = self.dynamic_confidence_score  # Overall confidence score 

            # Adjust probabilities based on classification:
            # If classified as benign, probability of being malicious is the complement of the confidence
            if dynamic_classification == 0:  
                P_dynamic = 1 - P_dynamic  

            # Weights for combining static and dynamic model results
            wd = 0.60  # Weight for dynamic analysis
            ws = 0.40  # Weight for static analysis

            # Combine probabilities using weights
            P_combined = (wd * P_dynamic) + (ws * P_static)

            # Certainty score: Distance from the neutral boundary (0.5)
            certainty_score = abs(P_combined - 0.5) * 100

            # Determine overall classification based on the combined probability
            # If combined probability is >= 0.5, classify as Malicious (1), else Benign (0)
            overall_classification = 1 if P_combined >= 0.5 else 0

            # Write combined classifications in terms of benign if both models classify as benign
            if dynamic_classification == 0 and static_classification == 0:
                P_combined = 1 - P_combined
            
            self.P_combined = P_combined
            self.certainty_score = certainty_score
            self.static_classification = static_classification
            self.dynamic_classification = dynamic_classification
            self.wd = wd
            self.ws = ws


            # Methodology details
            methodology = (
                f"Methodology:\n"
                f" - Combined Confidence: {self.P_combined*100:.2f}%\n"
                f" - Dynamic Weight (wd): {wd}\n"
                f" - Static Weight (ws): {ws}\n"
                f" - Distance from Neutral: {certainty_score:.2f}%\n"
                f" - Static Classification: {'Malicious' if static_classification == 1 else 'Benign'}\n"
                f" - Static Confidence: {np.max(self.static_predict_probability[0])*100:.2f}%\n"
                f" - Dynamic Classification: {'Malicious' if dynamic_classification == 1 else 'Benign'}\n"
                f" - Dynamic Confidence: {self.dynamic_confidence_score * 100:.2f}%\n"

            )

            # Display the overall classification result in the GUI
            if overall_classification == 1:
                classification_text = "Malicious"
                self.overall_class_display.setText(f"Overall Classification: {classification_text}\n{methodology}")
                self.overall_class_display.setStyleSheet("color: red; font-weight: bold;")
                self.logo = QLabel(self)
                self.logo.setPixmap(QPixmap("images/Designer(5).jpeg").scaled(200, 400, Qt.KeepAspectRatio))
                self.main_layout.addWidget(self.logo, 8, 0, 6, 1)  # Extend image vertically across 6 rows
                self.hybrid_class = "Malicious"

            else:
                classification_text = "Benign"
                self.overall_class_display.setText(f"Overall Classification: {classification_text}\n{methodology}")
                self.overall_class_display.setStyleSheet("color: green; font-weight: bold;")
                self.logo = QLabel(self)
                self.logo.setPixmap(QPixmap("images/Designer(6).jpeg").scaled(200, 400, Qt.KeepAspectRatio))
                self.main_layout.addWidget(self.logo, 8, 0, 6, 1)  # Extend image vertically across 6 rows
                self.hybrid_class = "Benign"
                
            # Log the results for debugging
            self.logs_display.append("Combined Probability Calculation Complete.")
            self.logs_display.append(f"Overall Classification: {classification_text}")
            
        except Exception as e:
            self.logs_display.append(f"Error computing overall classification: {e}")
            print(f"Error: {e}")


    #######################################################################################
    #                                      Reporting                                      #                       
    #######################################################################################
   
    @pyqtSlot()  
    def generate_analysis_report(self):
        """ Generate the overall report. """
        self.logs_display.append("Generating Report...")
        generate_report(self.apk_file, self.static_features, self.dynamic_features,
                             self.dynamic_explanation, self.hybrid_class,self.P_combined,self.wd,self.ws,
                             self.certainty_score,self.static_classification,self.static_predict_probability,
                             self.dynamic_classification,self.dynamic_confidence_score)
        self.logs_display.append("Report Generated.")
    
    #######################################################################################
    #                                       Logs                                          #                       
    #######################################################################################
        
    def clear_logs(self):
        """ Clear logs displayed in the aplicalation as a text file. """
        self.logs_display.clear()

    def save_logs(self):
        """ Save logs displayed in the aplicalation as a text file. """
        file_dialog = QFileDialog(self)
        file_dialog.setFileMode(QFileDialog.AnyFile)
        file_dialog.setNameFilter("Text Files (*.txt)")
        file_dialog.setDefaultSuffix("txt")
        file_dialog.setAcceptMode(QFileDialog.AcceptSave)
        if file_dialog.exec_():
            file_name = file_dialog.selectedFiles()[0]
            with open(file_name, 'w') as file:
                file.write(self.logs_display.toPlainText())


#######################################################################################
#                                       Main                                          #                       
#######################################################################################       

def main():
    '''
    Initializes the PyQt application. Creates an instance of the whiterAbbIt class. Displays the main window by calling show().
    Starts the application's event loop with exec_()
    '''
    app = QApplication(sys.argv)
    window = whiterAbbIt()
    window.show()
    sys.exit(app.exec_())
    

if __name__ == '__main__':
    main()