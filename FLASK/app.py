from flask import Flask, jsonify
import pandas as pd
import pickle
import os
from sklearn.base import BaseEstimator

# Initialize Flask app
app = Flask(__name__)

# Load pre-trained models
model_files = {
    "Infiltration": "models/Infiltration_random_forest_model.pkl",
}

models = {}
for attack_type, model_path in model_files.items():
    with open(model_path, 'rb') as model_file:
        model = pickle.load(model_file)
        if isinstance(model, BaseEstimator):
            models[attack_type] = model
        else:
            print(f"Loaded model type for {attack_type}: {type(model)}")
            raise ValueError(f"Model for {attack_type} is not a scikit-learn model")

@app.route('/process_logs', methods=['GET'])
def process_logs():
    try:
        # Read the Excel file from input_files directory
        file_path = 'input_files/headings.xlsx'
        data = pd.read_excel(file_path)

        # Print the first few rows of the data for debugging
        print("Data preview:", data.head())

        # Fill missing values with null
        data = data.fillna('null')

        # Select specific columns (A, P, AV)
        selected_columns = ['Destination Port', 'Flow Packets/s', 'ACK Flag Count']
        if not all(col in data.columns for col in selected_columns):
            raise ValueError(f"One or more columns from {selected_columns} are not in the data")

        features = data[selected_columns]

        # Print the selected features for debugging
        print("Selected features preview:", features.head())

        # Prepare a dictionary to store predictions for each model
        predictions = {}

        for attack_type, model in models.items():
            # Predict using each model
            preds = model.predict(features).tolist()
            if attack_type == "Infiltration":
                # Modify the prediction output for "Infiltration"
                preds = ["Infiltration" if pred == "BENIGN" else pred for pred in preds]
            predictions[attack_type] = preds

        return jsonify(predictions)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)