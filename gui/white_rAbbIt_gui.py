##################
#white rAbbIt GUI#   
##################

import sys
import os
import subprocess
import threading
import numpy as np
from PyQt5.QtCore import Qt, QTimer, pyqtSlot,  QThread
from PyQt5.QtGui import QPixmap, QFont
from PyQt5.QtWidgets import (QApplication, QMainWindow, QLabel, QPushButton, QTextEdit, QProgressBar,
                             QFileDialog, QGridLayout, QVBoxLayout, QWidget, QFrame)
import joblib
from static_feature_extraction_thread import FeatureExtractionWorker
from sklearn.ensemble import RandomForestClassifier
from static_analysis_XAI import static_XAI
####
import time
from emulator_thread import EmulatorThread 
####


#Defined the MalwareAnalyzer class. QMainWindow class provides a main application window.
class MalwareAnalyzer(QMainWindow):
    def __init__(self):
        super().__init__()

        #Set window properties- Title and size (position and dimensions) of the main window.
        self.setWindowTitle("White rAbbIt - Hybrid Android Malware Analysis Tool")
        self.setGeometry(100, 100, 1200, 800)

        #Appled dark theme and custom styles
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

        #Created grid layout of organizing widgets within main layout
        self.main_layout = QGridLayout()

        #Centered Application Name "white rAbbIt" and Description
        self.title_label = QLabel(self)
        formatted_text = 'white r<b><span style="color:#FF0000;">A</span></b>bb<span style="color:#FF0000;">I</span>t'
        self.title_label.setText(formatted_text)
        self.title_label.setFont(QFont('Arial', 24, QFont.Bold))
        self.title_label.setAlignment(Qt.AlignCenter)
        self.main_layout.addWidget(self.title_label, 0, 1, 1, 3)

        #Breif description of the tool below the tiles, centered.
        self.description_label = QLabel("A Hybrid Android Malware Analysis Tool")
        self.description_label.setFont(QFont('Arial', 14))
        self.description_label.setAlignment(Qt.AlignCenter)
        self.main_layout.addWidget(self.description_label, 1, 1, 1, 3)

        #white rAbbIt logo in the top-left corner and scaled to extend vertically across 3 rows
        self.main_logo = QLabel(self)
        self.main_logo.setPixmap(QPixmap("images/Designer(3).jpeg").scaled(200, 400, Qt.KeepAspectRatio))
        self.main_layout.addWidget(self.main_logo, 0, 0, 3, 1)  # Extend image vertically across 3 rows

        #Created "Select APK" button. Connects its click event to select_apk method
        self.select_button = QPushButton("Select APK")
        self.select_button.clicked.connect(self.select_apk)
        self.main_layout.addWidget(self.select_button, 2, 0)

        #Created "Static Analysis" button (red). Connects its click event to analyze_apk method 
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

        #Save Logs Button
        self.save_logs_button = QPushButton("Save Logs")
        self.save_logs_button.clicked.connect(self.save_logs)
        self.main_layout.addWidget(self.save_logs_button, 3, 0)

        #Clear Logs Button
        self.clear_logs_button = QPushButton("Clear Logs")
        self.clear_logs_button.clicked.connect(self.clear_logs)
        self.main_layout.addWidget(self.clear_logs_button, 4, 0)

        #Model Explanation Button. Connects its click event to show_model_explanation method
        self.model_insights_label = QLabel("XAI (LIME) Simplified Results")
        self.model_explanation_button = QPushButton("Model Explanation")
        self.model_explanation_button.clicked.connect(self.show_model_explanation)
        self.main_layout.addWidget(self.model_explanation_button, 5, 0)

        #Generate Report Button. Connects its click event to generate_report method
        self.report_button = QPushButton("Generate Report")
        self.report_button.clicked.connect(self.generate_report)
        self.main_layout.addWidget(self.report_button, 6, 0)

        #Static Feature Extraction Status. Initializes the progress bar's value and maximum
        self.feature_extraction_status_label = QLabel("Static Feature Extraction Status")
        self.feature_extraction_status = QProgressBar(self)
        self.feature_extraction_status.setValue(0)
        self.feature_extraction_status.setMaximum(100)
        self.thread = None
        self.main_layout.addWidget(self.feature_extraction_status_label, 3, 1)
        self.main_layout.addWidget(self.feature_extraction_status, 4, 1)

        #Static Malware analysis gauge. Initializes the progress bar's value and maximum
        self.analysis_gauge_label = QLabel("Static Malware Analysis Progress")
        self.analysis_gauge = QProgressBar(self)
        self.analysis_gauge.setValue(0)
        self.analysis_gauge.setMaximum(100)
        self.main_layout.addWidget(self.analysis_gauge_label, 3, 2)
        self.main_layout.addWidget(self.analysis_gauge, 4, 2)
        
        #Results gauge (confidence score)
        self.results_gauge_label = QLabel("Static Analysis Confidence Score")
        self.results_gauge = QProgressBar(self)
        self.results_gauge.setValue(0)
        self.results_gauge.setMaximum(100)
        self.main_layout.addWidget(self.results_gauge_label, 3, 3)
        self.main_layout.addWidget(self.results_gauge, 4, 3)

        #Created "Dynamic Analysis" button (red). Connects its click event to start_emulator method 
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
        
        #Dynamic Feature Extraction Status. Initializes the progress bar's value and maximum
        self.dynamic_feature_extraction_status_label = QLabel("Dynamic Feature Extraction Status")
        self.dynamic_feature_extraction_status = QProgressBar(self)
        self.dynamic_feature_extraction_status.setValue(0)
        self.dynamic_feature_extraction_status.setMaximum(100)
        self.thread = None
        self.main_layout.addWidget(self.dynamic_feature_extraction_status_label, 6, 1)
        self.main_layout.addWidget(self.dynamic_feature_extraction_status, 7, 1)

        #Dynamic Malware analysis gauge. Initializes the progress bar's value and maximum
        self.dynamic_analysis_gauge_label = QLabel("Dynamic Malware Analysis Progress")
        self.dynamic_analysis_gauge = QProgressBar(self)
        self.dynamic_analysis_gauge.setValue(0)
        self.dynamic_analysis_gauge.setMaximum(100)
        self.main_layout.addWidget(self.dynamic_analysis_gauge_label, 6, 2)
        self.main_layout.addWidget(self.dynamic_analysis_gauge, 7, 2)

        #Results gauge (confidence score)
        self.dynamic_results_gauge_label = QLabel("Dynamic Analysis Confidence Score")
        self.dynamic_results_gauge = QProgressBar(self)
        self.dynamic_results_gauge.setValue(0)
        self.dynamic_results_gauge.setMaximum(100)
        self.main_layout.addWidget(self.dynamic_results_gauge_label, 6, 3)
        self.main_layout.addWidget(self.dynamic_results_gauge, 7, 3)

        #Logs Display Area
        self.logs_display_label = QLabel("Application Logs")
        self.logs_display = QTextEdit(self)
        self.logs_display.setReadOnly(True)
        self.main_layout.addWidget(self.logs_display_label, 8, 1)
        self.main_layout.addWidget(self.logs_display, 9, 1, 7, 1)

        #Feature Summary Display Area 
        self.feature_summary_label = QLabel("Extracted Feature Summary")
        self.feature_summary_display = QTextEdit(self)
        self.feature_summary_display.setReadOnly(True)
        self.main_layout.addWidget(self.feature_summary_label, 8, 2)
        self.main_layout.addWidget(self.feature_summary_display, 9, 2, 7, 1)

        #XAI Display Area 
        self.model_insights_display = QTextEdit(self)
        self.model_insights_display.setReadOnly(True)
        self.main_layout.addWidget(self.model_insights_label, 8, 3)
        self.main_layout.addWidget(self.model_insights_display,  9, 3, 1, 1)

        #Overall Determination
        self.overall_class_label = QLabel("Hyrid Classification Results")
        self.overall_class_display = QTextEdit(self)
        self.overall_class_display.setReadOnly(True)
        self.main_layout.addWidget(self.overall_class_label, 10, 3)
        self.main_layout.addWidget(self.overall_class_display, 11, 3, 5, 1)

        #Create central widget and set layout
        container = QWidget()
        container.setLayout(self.main_layout)
        self.setCentralWidget(container)

        # Load the static trained model
        self.load_model()

        #######
        # Initialize EmulatorThread
        self.apk_file = None
        self.worker_thread = None
        self.emulator_thread = None
        
        self.emulator_dir = "Android/Sdk/emulator"
        self.emulator_command = "./emulator -avd Medium_Phone_API_27 -verbose -no-boot-anim -no-snapshot-load"
        self.adb_command = ["adb", "devices"]
        #######

    def load_model(self):
        #Load the pre-trained model from the joblib file 
        try:
            self.static_trained_model = joblib.load ("models/static/trained model/static_trained_model.joblib")
            self.logs_display.append ("Static Model Loaded Successfully")
        except Exception as e:
            self.logs_display.append(f"Error loading model {e}")

    @pyqtSlot()
    def select_apk(self):
        file_dialog = QFileDialog(self)
        file_dialog.setFileMode(QFileDialog.ExistingFile)
        apk_file, _ = file_dialog.getOpenFileName(self, "Select APK File", "", "APK Files (*.apk)")
        self.apk_file = apk_file
        # Update log display with selected APK info
        self.logs_display.append(f"Selected APK: {os.path.basename(apk_file)}")
        
        #Restart guages when new APK is selected 
        self.feature_extraction_status.setValue(0)
        self.analysis_gauge.setValue(0)
        self.results_gauge.setValue(0)

        # Remove the Android logo when a new APK is selected if present
        if hasattr(self, 'logo') and self.logo:
            self.logo.clear()
        
    @pyqtSlot()
    def analyze_apk(self):
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
        #############################
        #Create a dataframe of all features whose value is '1' (present)
        df_filtered = feature_presence_df.loc[:, feature_presence_df.eq(1).any()]
        # Display app name discovered in AndroidManifest.xml
        self.logs_display.append(f"App Name: {app_name}")
        # Display the count of extracted features 
        self.logs_display.append(f"Features present: {str(df_filtered.shape[1])}/{str(feature_presence_df.shape[1])}")
        # Display the extracted features 
        self.display_extracted_features(df_filtered)
        ##############################
        '''   
        # Display the count of extracted features 
        self.logs_display.append(f"Total features extracted: {str(feature_presence_df.shape[1])}")
        # Display the extracted features 
        self.display_extracted_features(feature_presence_df.columns)
        '''
        # Pass the DataFrame to run_static_analysis for predictions
        self.run_static_analysis(feature_presence_df)
        # Stop the thread
        self.thread.quit()

    def feature_extraction_error(self, error_message):
        self.logs_display.append(f"Error during feature extraction: {error_message}")
        # Stop the thread
        self.thread.quit()
    
    def display_extracted_features(self, columns):
        # Clear the display before showing new features
        self.feature_summary_display.clear()
        for col in columns:
            self.feature_summary_display.append(col)
    

    def run_static_analysis(self, feature_presence_df):
        # Conduct the status analysis
        if self.static_trained_model is not None:
            
            try:
                self.logs_display.append("Running static analysis on features...")
                
                #Classify APK file
                self.static_prediction = self.static_trained_model.predict(feature_presence_df)
                #Predicted probaboloties of the respective class for the input sample 
                #Computed to be passed to XAI function to determine connfidence level
                self.static_predict_probability = self.static_trained_model.predict_proba(feature_presence_df)
                
                #Update progress bar after analysis 
                self.analysis_gauge.setValue(100)
                self.logs_display.append("Static analysis completed.")


                if self.static_prediction[0] == 0:
                    self.logs_display.append(f"Static Analysis Classification Result: Benign")
                    self.logo = QLabel(self)
                    self.logo.setPixmap(QPixmap("images/Designer(6).jpeg").scaled(200, 400, Qt.KeepAspectRatio))
                    self.main_layout.addWidget(self.logo, 6, 0, 6, 1)  # Extend image vertically across 6 rows

                elif self.static_prediction[0] == 1:
                    self.logs_display.append(f"Static Analysis Classification Result: Malicious")
                    self.logo = QLabel(self)
                    self.logo.setPixmap(QPixmap("images/Designer(5).jpeg").scaled(200, 400, Qt.KeepAspectRatio))
                    self.main_layout.addWidget(self.logo, 6, 0, 6, 1)  # Extend image vertically across 6 rows

            except Exception as e:
                self.logs_display.append(f"Error during prediction: {e}")
        else:
            self.logs_display.append("Model not loaded, cannot make predictions")
        
        # Generate XAI explanation
        static_XAI(self, feature_presence_df)
        
        # Update  analysis confidence score gauge
        self.results_gauge.setValue(int(np.max(self.static_predict_probability[0])*100))
    
    
    
    def run_apk(self, apk_file):
        pass    

    def extract_features_from_logs(self, logs):
        pass
    

    def run_dynamic_analysis(self, apk_file):
        pass

    def process_logs(self, log_file):
        pass

    def update_analysis_gauge(self):
        pass

    def update_results_gauge(self):
        pass

    def generate_report(self):
        pass

    
    @pyqtSlot()
    def start_dynamic_analysis(self):
        """Start dynamic analysis by launching the emulator and installing APK."""
        try:
            if not self.apk_file:
                self.logs_display.append("Error: No APK file selected.")
                return
            
            # Create EmulatorThread to handle emulator and APK installation
            self.emulator_thread = EmulatorThread(
                self.emulator_dir, self.emulator_command, self.adb_command, self.apk_file
            )

            # Connect signals after the thread has been instantiated
            self.emulator_thread.emulator_started.connect(self.on_emulator_started)
            self.emulator_thread.emulator_ready.connect(self.on_emulator_ready)
            self.emulator_thread.apk_installed.connect(self.on_apk_installed)
            self.emulator_thread.feature_extraction_started.connect(self.start_feature_extraction)
            self.emulator_thread.error.connect(self.on_error)
            self.emulator_thread.log_signal.connect(self.update_logs_display)  # Connect log signal

            # Start the emulator thread
            self.emulator_thread.start()

        except Exception as e:
            self.logs_display.append(f"Error starting dynamic analysis: {e}")

    #@pyqtSlot()
    def on_emulator_started(self):
        """Update GUI when the emulator starts."""
        self.logs_display.append("Emulator started.")
    #@pyqtSlot()
    def on_emulator_ready(self):
        """Update GUI when the emulator is ready."""
        self.logs_display.append("Emulator is ready.")
    @pyqtSlot()
    def on_apk_installed(self):
        """Update GUI when APK is installed."""
        self.logs_display.append("APK installed successfully.")
        #Do i want to put next steps here
        
    @pyqtSlot(str)
    def on_error(self, error_msg):
        """Handle errors in the emulator or APK installation process."""
        self.logs_display.append(f"Error: {error_msg}")
    
    @pyqtSlot(str)
    def update_logs_display(self, log_message):
        """Update the logs display with messages from the emulator thread."""
        self.logs_display.append(log_message)

    def start_feature_extraction(self):
        pass
        '''"""Start feature extraction after APK installation."""
        self.logs_display.append("Starting feature extraction for dynamic analysis...")
        # Trigger feature extraction here
        '''
      
    def show_model_explanation(self):
        if hasattr(self, 'lime_explanation'):
                                
                self.model_insights_display.append(f"Predicted Class: {np.argmax(self.static_predict_probability[0])}")
                self.model_insights_display.append(f"Predicted Probability: {np.max(self.static_predict_probability[0]):.2f}")
                
                # Display top 10 features
                self.model_insights_display.append("Top 10 Features:")
                for feature, weight in self.lime_explanation.as_list():
                    self.model_insights_display.append(f"{feature}: {weight:.2f}")
        else:
            self.model_insights_display.append("No explanation available. Run static analysis first.")
      
        
    def clear_logs(self):
        self.logs_display.clear()

    def save_logs(self):
        #Save logs displayed in the aplicalation as a text file 
        file_dialog = QFileDialog(self)
        file_dialog.setFileMode(QFileDialog.AnyFile)
        file_dialog.setNameFilter("Text Files (*.txt)")
        file_dialog.setDefaultSuffix("txt")
        file_dialog.setAcceptMode(QFileDialog.AcceptSave)
        if file_dialog.exec_():
            file_name = file_dialog.selectedFiles()[0]
            with open(file_name, 'w') as file:
                file.write(self.logs_display.toPlainText())

def main():
    #Initializes the PyQt application. Creates an instance of the MalwareAnalyzer class. Displays the main window by calling show().
    #Starts the application's event loop with exec_()
    app = QApplication(sys.argv)
    window = MalwareAnalyzer()
    window.show()
    sys.exit(app.exec_())
    

if __name__ == '__main__':
    main()