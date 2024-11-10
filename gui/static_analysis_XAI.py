################################################
#Explain static analysis prediction using LIME.#
# ##############################################  
"""
LIME gives a local explanation: it explains why a model made a specific prediction for 
a specific instance by highlighting which features contributed the most.
"""

from lime.lime_tabular import LimeTabularExplainer
import numpy as np
import json


def static_XAI(self, feature_presence_df):
    try:

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
                #Specifies the instance_to_explain as the input data row for which the explanation is generated.
                data_row=instance_to_explain,
                # Prediction function from trained model
                predict_fn=self.static_trained_model.predict_proba,
                # Number of features to include in explanation (10 most influential)
                num_features=10
            )
            #Convert explanation object to list 
            explanation_list = explanation.as_list()

            # Get predict_proba output to a list 
            predict_proba = self.static_trained_model.predict_proba(instance_to_explain.reshape(1, -1))[0].tolist()

            # Create a dictionary to store explanation and predict_proba for later LLM  generated report
            explanation_dict = {
                'explanation': explanation_list,
                'predict_proba': {
                    'Benign': predict_proba[0],
                    'Malicious': predict_proba [1]
                }
            }

            # Save explanation to JSON
            with open('explanation.json', 'w') as f:
                json.dump(explanation_dict, f)


            # Display explanation
            self.logs_display.append("LIME explanation completed")

            # Store the explanation object as an instance variable for the show_model_explanation()
            self.lime_explanation = explanation
            
    except Exception as e:
        self.logs_display.append(f"Error generating LIME explanation: {str(e)}")
