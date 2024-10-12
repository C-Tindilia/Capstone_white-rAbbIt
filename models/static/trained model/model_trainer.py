#############################################################
#Contains functions for training the machine learning model.#
#############################################################

'''
The model will not be fitted during runtime. The fitted model will be saved using joblib. 
The function also saves the dataframe that was used to train the data to a CSV so later 
the feature extractor can use it to correctly order the feature it extracts. 

For more information about how the data for this model was sourced, cleaned, preprocessed, 
etc. see the notebook file:

    '/home/white-rabbit/Desktop/Capstone- white rAbbIt/models/static/End to End Model Building/white_rabbit_Static_Analysis_ExplainableAI.ipynb'

The notebook file also contains modeling and evaluation steps and demonstrates XAI functionality.

'''

from data_loader import load_dataset
from X_y_separation import extract_features
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from imblearn.over_sampling import SMOTE
import joblib


def train_model(X, y, model_path):
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    smote = SMOTE()
    #Resample the dataset
    X_train_resampled, y_train_resampled = smote.fit_resample(X_train, y_train)
    #Train the Random Forest model
    rf_model = RandomForestClassifier()
    rf_model.fit(X_train_resampled, y_train_resampled)
    #Saves the state of the computation so that th ML model can be loaded in Python
    joblib.dump(rf_model, model_path)
    #Saves the dataframe that was used to train the data to a CSV so tlater the feature 
    #extractor can correctly order the features 
    X_train_resampled.to_csv('models/static/trained model/static_training_df.csv',index=False)
    

#Specify the file path
file_path = 'data/static analysis dataset/cleaned data/cleaned_preprocessed_drebin.csv'
#Call the load_dataset function with the file path
df = load_dataset(file_path)
#X and Y and feature extraction
X, y, extracted_feature_list = extract_features(df)
model_path = 'models/static/trained model/static_trained_model.joblib'
train_model(X, y, model_path)

