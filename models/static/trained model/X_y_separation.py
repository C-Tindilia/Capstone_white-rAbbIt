######################################################
#Contains function for separating features and labels#
######################################################

import pandas as pd
from data_loader import load_dataset


def extract_features(df):
    #Separate features and labels
    X = df.drop(columns=['class'])
    y = df['class']
    extracted_features_list = X.columns.tolist()
    return X, y, extracted_features_list



