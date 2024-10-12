#####################
#Classification PoC #
#####################

'''
This is for informational and testing puposes only. Demonstrates running predictions
on the 2D df of features and occurences. 

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

def classify_apk(apk_file_feat):
    #Load the model
    loaded_model = load('models/static/trained model/static_trained_model.joblib')
    #Classify APK file
    prediction = loaded_model.predict(apk_file_feat)
    return prediction


apk_file_feat = pd.read_csv('models/static/APK Example Features/Benign/demo_apk_4.csv')
classification = classify_apk(apk_file_feat)

print(apk_file_feat)
print(classification[0])

