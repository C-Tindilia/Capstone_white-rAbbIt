#####################
#Classification PoC #
#####################

'''
This is for informational and testing puposes only. Demonstrates running predictions
on the 2D df of features and occurences and provides XAI local interpretibility

Update apk_file_feat with whichever test files you desire.
Files are available in the following directorires:
    /home/white-rabbit/Desktop/Capstone- white rAbbIt/models/static/APK Example Features/Benign
    /home/white-rabbit/Desktop/Capstone- white rAbbIt/models/static/APK Example Features/Malicious
'''

#Contains functions for performing static analysis clasification

from joblib import load
from sklearn.ensemble import RandomForestClassifier
from X_y_separation import extract_features
import pandas as pd
from lime.lime_tabular import LimeTabularExplainer
import numpy as np
import json

def classify_apk(apk_file_feat):
    #Load the model
    loaded_model = load('models/static/trained model/static_trained_model.joblib')
    #Classify APK file
    prediction = loaded_model.predict(apk_file_feat)
    certainty = loaded_model.predict_proba
    return prediction, certainty


apk_file_feat = pd.read_csv('models/static/APK Example Features/Benign/demo_apk_5.csv')
classification, certainty = classify_apk(apk_file_feat)

print(apk_file_feat)
print(classification[0])
print(certainty)


def static_XAI(feature_presence_df,certainty):

    feature_array = feature_presence_df.to_numpy()

    classification_names = ['Benign', 'Malicious']

    explainer = LimeTabularExplainer(
        # Training data for explainer
        training_data=feature_array,
        # Feature names from DataFrame columns
        feature_names=feature_presence_df.columns.tolist(),
        #Class labels
        class_names=classification_names,
        mode='classification' 
    )

        # Select the first instance to explain
    instance_to_explain = feature_array[0]

    explanation = explainer.explain_instance(
        data_row=instance_to_explain,
        # Prediction function from trained model
        predict_fn= certainty,
        # Number of features to include in explanation
        num_features=10
    )

    #Convert explanation object to list 
    explanation_list = explanation.as_list()

    # Get predict_proba output to a list 
    predict_proba = certainty(instance_to_explain.reshape(1, -1))[0].tolist()

    # Create a dictionary to store explanation and predict_proba for later LLM  generated report
    explanation_dict = {
        'explanation': explanation_list,
        'predict_proba': {
            'Benign': predict_proba[0],
            'Malicious': predict_proba [1]
        }
    }
        
    

    # Save explanation to JSON
    with open('explanation_benign_demo.json', 'w') as f:
        json.dump(explanation_dict, f)

static_XAI(apk_file_feat,certainty)