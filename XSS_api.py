from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
from waitress import serve

app = Flask(__name__)
CORS(app)  # Allow Cross-Origin Resource Sharing

# Load the best model
model = joblib.load('best_xss_model_count_vectorizer_v1.pkl')

@app.route('/note', methods=['POST'])
def check_note():
    note = request.json.get('note')
    if note is None:
        return jsonify({"error": "No note provided"}), 400

    # Predict XSS for the note
    prediction_xss = model.predict([note.lower()])

    response = {
        "is_xss": bool(prediction_xss[0]),  # Ensure to access the first element of the prediction
    }

    if response["is_xss"]:
        response["message"] = "XSS detected in note"
    else:
        response["message"] = "No injection detected"
        
    return jsonify(response)

if __name__ == '__main__':
    serve(app, host='0.0.0.0', port=4090)
