from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.feature_extraction.text import TfidfVectorizer
import pandas as pd
import warnings
import joblib
import os

def traindata(data, output_result=True, random_state_val=42):
    vectorizer = TfidfVectorizer()
    warnings.filterwarnings("ignore")

    # converts the dict of lists to dataframe
    df = pd.DataFrame(data)
    
    # this drops the row if the row of data does not contain "Email Type", this is to filter out data without a value to train on
    df = df.dropna(subset=["body"])

    # this creates the x and y calues that the data is trained on, this is where the correlation between X and Y can be found usin the ML model 
    X = df["body"]
    y = df["type"]
    
    # this changes the characters form the body into a vercor (a value) that the ML can correlate
    X = vectorizer.fit_transform(X)

    # test size of 0.2 (20%) this is standard (80/20 split), the random state is just a random number to use
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=random_state_val)

    # n_estimator is the number of trees that the model uses, high is more accurate but slower
    rf_classifier = RandomForestClassifier(n_estimators=100, random_state=random_state_val)
    rf_classifier.fit(X_train, y_train)             # this trains the model that was just created on the previous line

    # this creates a prediction on the X_test set based on the training on the X_train set
    y_pred = rf_classifier.predict(X_test)

    if output_result:
        
        accuracy = accuracy_score(y_test, y_pred) # this will create an accuracy score where it compares the y_pred on the actual values to see how accurate the model is
        classification_rep = classification_report(y_test, y_pred) # this creates a report based on the accuracy
        
        print(f"Accuracy: {accuracy:.2f}")
        print("\nClassification Report:\n", classification_rep)

    os.makedirs("ml/models", exist_ok=True)

    joblib.dump(rf_classifier, "phishing-email-analysis/ml/models/model.pkl")
    joblib.dump(vectorizer, "phishing-email-analysis/ml/models/vectorizer.pkl")
    