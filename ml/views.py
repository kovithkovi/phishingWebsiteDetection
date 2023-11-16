import joblib
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from sklearn.feature_extraction.text import TfidfVectorizer
from django.http import JsonResponse
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import roc_curve, auc


@csrf_exempt
def index(request):
    if request.method == 'POST':
        url = request.POST.get('url')
        # Load your dataset (replace 'your_dataset.csv' with your data)
        df = pd.read_csv("C:/records/env/ml/ml/static/dataset_phishing.csv")

        # Assuming 'status' is the column containing labels (0 for safe, 1 for phishing)
        # Remove the 'status' column as it's the label
        X = df.drop('status', axis=1)
        y = df['status']

        # Extract features from URLs using TF-IDF (you can use other methods as well)
        vectorizer = TfidfVectorizer()
        # Assuming 'url' is the column containing the URLs
        X = vectorizer.fit_transform(X['url'])

        # Create and train a Random Forest Classifier (you can try other algorithms)
        clf = RandomForestClassifier(n_estimators=100, random_state=42)
        clf.fit(X, y)
        # Take user input for a URL to classify
        user_input_url = url

        # Extract features from the user input URL using the same TF-IDF vectorizer
        user_input_features = vectorizer.transform([user_input_url])

        # Make a prediction
        prediction = clf.predict(user_input_features)

        # Interpret the prediction
        if prediction[0] == 1:
            result = "Not Safe"
            print("Phishing: The provided URL is classified as phishing.")
        else:
            result = "Safe"
            print("Safe: The provided URL is classified as safe.")

    return render(request, 'index.html', {'url': result})
