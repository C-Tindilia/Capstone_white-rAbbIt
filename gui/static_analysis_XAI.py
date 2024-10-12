################################################
#Explain static analysis prediction using LIME.#
# ##############################################  
"""
LIME gives a local explanation: it explains why a model made a specific prediction for 
a specific instance by highlighting which features contributed the most.
"""

from lime.lime_tabular import LimeTabularExplainer
import numpy as np


def static_XAI(self, feature_presence_df):

    self.logs_display.append("Preparing LIME explanation...")
  
    if self.static_trained_model is not None:
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
            predict_fn=self.static_trained_model.predict_proba,
            # Number of features to include in explanation
            num_features=10
        )

        # Save explanation to HTML file
        explanation.save_to_file('lime_explanation_.html')

        # Display explanation
        self.logs_display.append("LIME explanation completed")

        # Store the explanation object as an instance variable for the show_model_explanation()
        self.lime_explanation = explanation
        
