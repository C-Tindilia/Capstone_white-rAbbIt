# main_analysis.py

# Importing the necessary modules for static and dynamic analysis
import static_analysis  # This module handles static analysis of the APK (permissions, API calls, strings extraction)
import dynamic_analysis  # This module handles dynamic analysis (log collection, system calls, file monitoring, network capture)
import pandas as pd  # Importing pandas to work with data and combine the static and dynamic analysis results

def combine_features(static_features, dynamic_features):
    """
    Combines static and dynamic features into a single dataset.
    
    Parameters:
        static_features (dict): A dictionary containing features from static analysis??
        dynamic_features (dict): A dictionary containing features from dynamic analysis??
    
    Returns:
        pd.DataFrame: A DataFrame with all the combined features.
    """
    # Merging the static and dynamic features into a single dictionary
    combined = {**static_features, **dynamic_features}
    
    # Creating a pandas DataFrame from the combined dictionary
    df = pd.DataFrame([combined])
    
    # Saving the combined dataset to a CSV file named 'combined_analysis_results.csv'
    df.to_csv('combined_analysis_results.csv', index=False)
    
    # Return the DataFrame for further use (if needed)
    return df

# Main script execution begins here
if __name__ == '__main__':
    # Define the path to the APK file and the decompiled APK folder for static analysis
    apk_path = 'path_to_your_apk.apk'  # This is the path where the APK file is located
    decompiled_folder = 'path_to_decompiled_apk'  # Path to the folder where the APK has been decompiled (using tools like apktool)

    # Grab the Running Static Analysis
    print("Running Static Analysis...")
    
    # The run_static_analysis() function from static_analysis.py is called here
    # It extracts static features like permissions, API calls, and strings from the APK
    static_results = static_analysis.run_static_analysis(apk_path, decompiled_folder)
    
    # Grab the Running Dynamic Analysis
    print("Running Dynamic Analysis...")
    
    # The run_dynamic_analysis() function from dynamic_analysis.py is called here
    # It collects dynamic features such as logs, system calls, file system changes, and network activity
    dynamic_results = dynamic_analysis.run_dynamic_analysis()
    
    # Combining Static and Dynamic Features 
    print("Combining Static and Dynamic Features...")
    
    # Calling the combine_features() function to merge static and dynamic features into a single dataset
    combined_df = combine_features(static_results, dynamic_results)
    
    # Notify the user that the combined analysis is completed and the results are saved in a CSV file
    print("Analysis completed. Combined results saved to 'combined_analysis_results.csv'.")
