from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from waitress import serve

app = Flask(__name__)
CORS(app)  # Allow Cross-Origin Resource Sharing

# Load the trained models for SQL injection and XSS detection
model_sql = joblib.load('best_model_sql_1,48,000 payloads.pkl')
model_xss = joblib.load('best_xss_model_count_vectorizer_v1.pkl')

@app.route('/sql_injection', methods=['POST'])
def detect_injections_api():
    username = request.json.get('username')
    password = request.json.get('password')
    
    if username is None or password is None:
        return jsonify({"error": "Username and password are required"}), 400

    # Predict SQL injection for username and password
    prediction_sql_username = model_sql.predict([username.lower()])
    prediction_sql_password = model_sql.predict([password.lower()])

    response = {
        "username_is_sql_injection": bool(prediction_sql_username[0]),  # Access the first element of the prediction
        "password_is_sql_injection": bool(prediction_sql_password[0]),  # Access the first element of the prediction
    }

    if response["username_is_sql_injection"] or response["password_is_sql_injection"]:
        response["message"] = "Malicious input detected"
    else:
        response["message"] = "No injection detected"

    return jsonify(response)

@app.route('/note', methods=['POST'])
def check_note():
    note = request.json.get('note')
    
    if note is None:
        return jsonify({"error": "No note provided"}), 400

    # Predict XSS for the note
    prediction_xss = model_xss.predict([note.lower()])

    response = {
        "is_xss": bool(prediction_xss[0]),  # Ensure to access the first element of the prediction
    }

    if response["is_xss"]:
        response["message"] = "Malicious input detected"
    else:
        response["message"] = "No injection detected"
        
    return jsonify(response)

if __name__ == '__main__':
    serve(app, host='0.0.0.0', port=4090)
