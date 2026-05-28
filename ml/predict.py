import joblib
import os

model = None
vectorizer = None

# loads the model is
def load_model():
    global model, vectorizer
    if os.path.exists("phishing-email-analysis/ml/models/model.pkl"):
        model = joblib.load("phishing-email-analysis/ml/models/model.pkl")
        vectorizer = joblib.load("phishing-email-analysis/ml/models/vectorizer.pkl")
        return True
    return False

def predict(email_body):
    # vectorize the email using the same vectorizer used in training
    X = vectorizer.transform([email_body])

    # get the prediction and confidence score from the model
    prediction = model.predict(X)[0]
    confidence = model.predict_proba(X)[0][prediction]

    return {
        "prediction": prediction,
        "confidence": confidence
    }
    