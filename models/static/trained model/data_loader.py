############################################
#Contains functions for loading the dataset#
############################################

'''
The data has already been cleaned and preprocessed (handled missing values/encoding/
validating binary features, etc.) These steps have been documented in the following file:
    
    'models/static/End to End Model Building/white_rabbit_Static_Analysis_ExplainableAI.ipynb'
 '''

import pandas as pd

def load_dataset(file_path):
    #Function for loading the dataset 
    df = pd.read_csv(file_path)
    return df

