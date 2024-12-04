#######################################################################################
#                                   Report Generation                                 #                       
#######################################################################################
'''
Generate a detailed Android malware analysis report.

This function interacts with the OpenAI API to generate a malware analysis report 
based on static and dynamic features extracted from an Android APK, along with 
hybrid classification results.
'''

import openai
import os
import numpy as np
from datetime import datetime
from PIL import Image
from fpdf import FPDF

# Set your OpenAI API key
api_key = os.getenv("OPENAI_API_KEY")
openai.api_key = api_key

def generate_report(apk_file, static_features, dynamic_features,xai_openai, hybrid_class,P_combined,wd,ws,certainty_score,static_classification,static_predict_probability,dynamic_classification,dynamic_confidence_score
):
    # Construct the prompt for the OpenAI API
    prompt = f"""
    You are generating a detailed Android malware analysis report based on the following data:
    Extracted Static Features: {static_features}
    Extracted Dynamic Features: {dynamic_features}
    XAI Results for Dynamic Analysis: {xai_openai}
    Hybrid Classification: {hybrid_class}
    Combined Confidence: {P_combined}
    Dynamic Weight: {wd}
    Static Weight: {ws}
    Distance from Neutral: {certainty_score}
    Static Classification: {static_classification}
    Static Confidence: {np.max(static_predict_probability[0])*100:.2f}
    Dynamic Classification: {dynamic_classification}
    Dynamic Confidence: {dynamic_confidence_score * 100:.2f}
    The report will be in the following format 

    -----------Overview ----------- 
    Summarize the purpose and security status of the app. Highlight any behaviors aligned with known malware types or attack vectors.

    ----------- Static Features -----------
    The following static features were detected in the APK:
    {static_features}
    Categorize features by behavior (e.g., SMS control, device tracking). Cross-reference with known malware patterns.
    Explain each permission's potential impact on security, with context for malicious behaviors.

    ----------- Dynamic Features -----------
    The following dynamic features were detected during the behavioral analysis of the APK:
    {dynamic_features}
    Further explain the dynamic features and their potential impact on security with context for malicious behaviors. 

    ----------- Malware Type  -----------
     Based on the analysis of both static and dynamic features, what do you think the malware type is?
    
    """

    try:
        # Send the request to OpenAI API using the chat completions endpoint
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",  # Use model for chat completions
            messages=[
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=4096,  # Increase response length for the explanation
            temperature=0  # Deterministic output
        )
        
        # Parse the JSON response from the model
        output = response['choices'][0]['message']['content'].strip()
        
        # Format the report 
        report_content = output
        
        # Save the report as a PDF
        save_report_as_pdf(report_content, apk_file)

        return report_content

    except Exception as e:
        print(f"Error: {e}")
        return None



def save_report_as_pdf(report_content, apk_file, filename="malware_analysis_report.pdf"):
    """ Save the generated malware analysis report to a PDF file. """
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=10)  # Adjust margin for more compactness
    pdf.add_page()

    # Set the font for the title (smaller font size)
    pdf.set_font("Arial", 'B', 16)  # Slightly larger title font
    pdf.cell(200, 10, txt="white rAbbIt Android Malware Analysis Report", ln=True, align='C')

    # Add a line break
    pdf.ln(10)  # Adjust space between title and content

    # Set the font for the content (smaller font size and line spacing)
    pdf.set_font("Arial", size=12)  # Adjusted for readability

    # Date of analysis
    date_of_analysis = datetime.now().strftime("%B %d, %Y")
    pdf.cell(0, 10, f"Date of Analysis: {date_of_analysis}", ln=True)

    # Environment Details 
    environment_details = "Pixel_2_API_27"
    pdf.cell(0, 10, f"Emulator: {environment_details}", ln=True)

    # APK Sample
    pdf.set_font("Arial", size=10)  # Ensure appropriate font size
    pdf.multi_cell(0, 10, f"Sample: {apk_file}")

    # Add a line break
    pdf.ln(10)

    # Adjust the left and right margins for better fit
    pdf.set_left_margin(15)
    pdf.set_right_margin(15)

    # Break the report content into lines to fit in the PDF
    lines = report_content.split('\n')
    for line in lines:
        pdf.multi_cell(0, 8, line)  # Adjusted line height for compactness
        pdf.ln(2)  # Extra line space between sections if needed

    # Static Analysis Model Info
    pdf.ln(10)
    pdf.set_font("Arial", size=12)  # Bold for section titles
    pdf.cell(0, 8, f"----------- Static Model Information -----------", ln=True)
    pdf.set_font("Arial", size=12)  # Regular font for content
    pdf.multi_cell(0, 8, "Static Analysis Model: Random Forest Classifier\n"
                          "Training Data: Drebin (15,036 samples)\n"
                          "Preprocessing: Feature extraction based on API calls, permissions, command signatures, and intent actions.\n"
                          "Evaluation Metrics:\n"
                          "Accuracy: 98.77%\n"
                          "Precision: 98.73%\n"
                          "F1-Score: 98.33%\n"
                          "ROCAUC: 99.94%\n")

    # Dynamic Analysis Model Info
    pdf.ln(10)
    pdf.set_font("Arial", size=12)  # Bold for section titles
    pdf.cell(0, 8, f"----------- Dynamic Model Information -----------", ln=True)
    pdf.set_font("Arial", size=12)  # Regular font for content
    pdf.multi_cell(0, 8, "Dynamic Analysis Model: Large Language Model (LLM) - GPT-3.5-turbo\n"
                          "Application: Used for analyzing network traffic data from an Android APK runtime.\n"
                          "Approach: The LLM processes logs and classifies whether the application is benign or malicious based on behavioral patterns found in their network traffic statistics.\n")

    # Hybrid Malware Analysis Methodology Section
    pdf.add_page()  # Add a new page for the image
    pdf.ln(10)  # Add some space before the image
    pdf.cell(0, 8, f"----------- Hybrid Malware Analysis Methodology -----------", ln=True)
    image_path = "images/Hybrid_Class_Calc.png"  

    # Calculate image dimensions while preserving aspect ratio
    with Image.open(image_path) as img:
        # Get the image width and height
        img_width, img_height = img.size
        
        # Define the maximum width for the image
        max_width = 200
        
        # Calculate the scaling factor based on the width
        scale_factor = max_width / img_width
        scaled_height = img_height * scale_factor
        
        # Insert the image into the PDF with the scaled dimensions
        pdf.image(image_path, x=15, y=pdf.get_y(), w=max_width, h=scaled_height)

    # Output the PDF to a file
    pdf.output(filename)
    print(f"Report saved as {filename}")



