from flask import Flask, render_template, request, jsonify, session
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import pickle
import os
from werkzeug.utils import secure_filename
import json

app = Flask(__name__)
app.secret_key = 'your-secret-key-here-change-in-production'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Create necessary folders
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs('models', exist_ok=True)

# Global variables to store models and preprocessors
models = {}
scaler = None
label_encoders = {}
feature_columns = None
attack_types = None

def preprocess_data(df):
    """Preprocess the network traffic data"""
    global scaler, label_encoders, feature_columns, attack_types
    
    # Make a copy
    df = df.copy()
    
    # Remove any unnamed columns
    df = df.loc[:, ~df.columns.str.contains('^Unnamed')]
    
    # Assume last column is the label/target
    if 'label' not in df.columns and 'attack_type' not in df.columns:
        df.rename(columns={df.columns[-1]: 'label'}, inplace=True)
    
    target_col = 'label' if 'label' in df.columns else 'attack_type'
    
    # Store attack types
    attack_types = df[target_col].unique().tolist()
    
    # Separate features and target
    X = df.drop(columns=[target_col])
    y = df[target_col]
    
    # Encode categorical features
    label_encoders = {}
    for col in X.columns:
        if X[col].dtype == 'object':
            le = LabelEncoder()
            X[col] = le.fit_transform(X[col].astype(str))
            label_encoders[col] = le
    
    # Store feature columns
    feature_columns = X.columns.tolist()
    
    # Scale features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    # Encode target
    le_target = LabelEncoder()
    y_encoded = le_target.fit_transform(y)
    label_encoders['target'] = le_target
    
    return X_scaled, y_encoded, X.columns.tolist()

def train_models(X_train, X_test, y_train, y_test):
    """Train multiple ML models"""
    results = {}
    
    # Random Forest
    print("Training Random Forest...")
    rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    rf.fit(X_train, y_train)
    rf_pred = rf.predict(X_test)
    models['random_forest'] = rf
    
    results['random_forest'] = {
        'accuracy': float(accuracy_score(y_test, rf_pred)),
        'confusion_matrix': confusion_matrix(y_test, rf_pred).tolist(),
        'classification_report': classification_report(y_test, rf_pred, output_dict=True)
    }
    
    # SVM (on a sample for speed)
    print("Training SVM...")
    sample_size = min(5000, len(X_train))
    indices = np.random.choice(len(X_train), sample_size, replace=False)
    svm = SVC(kernel='rbf', random_state=42)
    svm.fit(X_train[indices], y_train[indices])
    svm_pred = svm.predict(X_test)
    models['svm'] = svm
    
    results['svm'] = {
        'accuracy': float(accuracy_score(y_test, svm_pred)),
        'confusion_matrix': confusion_matrix(y_test, svm_pred).tolist(),
        'classification_report': classification_report(y_test, svm_pred, output_dict=True)
    }
    
    # Neural Network
    print("Training Neural Network...")
    nn = MLPClassifier(hidden_layer_sizes=(100, 50), max_iter=50, random_state=42)
    nn.fit(X_train, y_train)
    nn_pred = nn.predict(X_test)
    models['neural_network'] = nn
    
    results['neural_network'] = {
        'accuracy': float(accuracy_score(y_test, nn_pred)),
        'confusion_matrix': confusion_matrix(y_test, nn_pred).tolist(),
        'classification_report': classification_report(y_test, nn_pred, output_dict=True)
    }
    
    return results

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    """Handle dataset upload"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if file and file.filename.endswith('.csv'):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        # Store filepath in session
        session['dataset_path'] = filepath
        
        # Read and get basic info
        df = pd.read_csv(filepath)
        
        return jsonify({
            'success': True,
            'message': 'File uploaded successfully',
            'rows': len(df),
            'columns': len(df.columns),
            'filename': filename
        })
    
    return jsonify({'error': 'Invalid file type. Please upload a CSV file'}), 400

@app.route('/train', methods=['POST'])
def train():
    """Train models on uploaded dataset"""
    if 'dataset_path' not in session:
        return jsonify({'error': 'Please upload a dataset first'}), 400
    
    try:
        # Load dataset
        df = pd.read_csv(session['dataset_path'])
        
        # Preprocess
        X, y, features = preprocess_data(df)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.3, random_state=42
        )
        
        # Train models
        results = train_models(X_train, X_test, y_train, y_test)
        
        # Save models
        with open('models/random_forest.pkl', 'wb') as f:
            pickle.dump(models['random_forest'], f)
        with open('models/scaler.pkl', 'wb') as f:
            pickle.dump(scaler, f)
        with open('models/label_encoders.pkl', 'wb') as f:
            pickle.dump(label_encoders, f)
        with open('models/feature_columns.pkl', 'wb') as f:
            pickle.dump(feature_columns, f)
        with open('models/attack_types.pkl', 'wb') as f:
            pickle.dump(attack_types, f)
        
        return jsonify({
            'success': True,
            'results': results,
            'message': 'Models trained successfully'
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/predict', methods=['POST'])
def predict():
    """Make prediction on new data"""
    try:
        # Load models if not in memory
        if not models or scaler is None:
            load_models()
        
        data = request.json
        model_type = data.get('model', 'random_forest')
        
        # Get features
        features_dict = data.get('features', {})
        
        # Create DataFrame
        df = pd.DataFrame([features_dict])
        
        # Encode categorical features
        for col in df.columns:
            if col in label_encoders and col != 'target':
                if df[col].dtype == 'object':
                    try:
                        df[col] = label_encoders[col].transform(df[col].astype(str))
                    except:
                        df[col] = 0  # Unknown category
        
        # Ensure all feature columns are present
        for col in feature_columns:
            if col not in df.columns:
                df[col] = 0
        
        # Reorder columns
        df = df[feature_columns]
        
        # Scale
        X_scaled = scaler.transform(df)
        
        # Predict
        model = models.get(model_type, models['random_forest'])
        prediction = model.predict(X_scaled)[0]
        prediction_proba = model.predict_proba(X_scaled)[0] if hasattr(model, 'predict_proba') else None
        
        # Decode prediction
        attack_type = label_encoders['target'].inverse_transform([prediction])[0]
        
        result = {
            'prediction': attack_type,
            'is_attack': attack_type.lower() != 'normal',
            'confidence': float(max(prediction_proba)) if prediction_proba is not None else None
        }
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def load_models():
    """Load saved models"""
    global models, scaler, label_encoders, feature_columns, attack_types
    
    try:
        with open('models/random_forest.pkl', 'rb') as f:
            models['random_forest'] = pickle.load(f)
        with open('models/scaler.pkl', 'rb') as f:
            scaler = pickle.load(f)
        with open('models/label_encoders.pkl', 'rb') as f:
            label_encoders = pickle.load(f)
        with open('models/feature_columns.pkl', 'rb') as f:
            feature_columns = pickle.load(f)
        with open('models/attack_types.pkl', 'rb') as f:
            attack_types = pickle.load(f)
    except FileNotFoundError:
        pass

@app.route('/status')
def status():
    """Get system status"""
    return jsonify({
        'models_trained': len(models) > 0,
        'available_models': list(models.keys()),
        'dataset_loaded': 'dataset_path' in session
    })

if __name__ == '__main__':
    app.run(debug=True, port=5000)