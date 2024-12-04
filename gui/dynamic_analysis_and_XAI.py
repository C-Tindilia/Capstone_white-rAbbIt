########################################################################
#Conducts dynamic analysis and provides XAI Insights. Leverages Openai #
######################################################################## 
'''
This function classifies APK network traffic data as benign or malicious based on the 
entire input data. Also, provide an explanation for the classification.

Note: You must store the OpenAI API key securely in an environment variable named OPENAI_API_KEY
for this to run.
'''

import openai
import os

# Set your OpenAI API key
api_key = os.getenv("OPENAI_API_KEY")
openai.api_key = api_key

def classify_apk_network_traffic(log_str: str):

    # Define the prompt for the entire runtime data with an explanation request
    prompt = f"""
    Analyze the following network traffic data from an Android APK runtime. 
    Determine whether the behavior indicates malicious activity (1) or benign behavior (0). 
    Additionally, provide a confidence score between 0 and 1 for your classification.
    
    After classifying, explain why you arrived at this decision and describe the key elements of the traffic 
    data that influenced your classification. Provide a detailed reasoning behind the confidence score as well.
    And explain how the model weighed the importance of different features. 

    Network Traffic Data:
    {log_str}

    Your response should be in the following format:
    {{
        "Predicted Class": 1 or 0,
        "Predicted Probability": confidence_score,
        "Key Features": [
            {{
                "Feature": "Feature Name",
                "Impact": "High/Medium/Low",
                "Explanation": "Explanation of why this feature is important"
            }},
            ...
        ]
    }}
    """
    
    try:
        # Send the request to OpenAI API using the chat completions endpoint
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",  # Use an appropriate model for chat completions
            messages=[
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=600,  # Increase response length for the explanation
            temperature=0  # Deterministic output
        )
        
        # Parse the JSON response from the model
        output = response['choices'][0]['message']['content'].strip()
        
        # Convert the output to a dictionary
        result = eval(output)  # Ensure trusted input; use `json.loads` for untrusted input
        
        # Extract classification, confidence, and explanation
        predicted_class = result["Predicted Class"]
        predicted_probability = result["Predicted Probability"]
        key_features = result["Key Features"]
        
        # Format the key features into a string for easier display
        key_features_str = "\n".join([f"- Feature: {feature['Feature']}, Impact: {feature['Impact']}, "
                                     f"Explanation: {feature['Explanation']}" for feature in key_features])
        
        # Return the formatted results
        explanation = f"""
        Predicted Class: {predicted_class}
        Predicted Probability: {predicted_probability}
        Key Features:
        {key_features_str}
        """
        print(predicted_class)
        print(predicted_probability)
        print(explanation)
        
        return predicted_class, predicted_probability, explanation
    
    except Exception as e:
        print(f"Error: {e}")
        return None, None, None


