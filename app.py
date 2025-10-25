from flask import Flask, render_template, request, jsonify, session
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import pickle
import os
from werkzeug.utils import secure_filename
import json
from collections import Counter

try:
    from imblearn.over_sampling import SMOTE
except ImportError:  # pragma: no cover - installed via requirements.txt
    SMOTE = None

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
class_distribution = None

def preprocess_data(df):
    """Preprocess the network traffic data"""
    global scaler, label_encoders, feature_columns, attack_types, class_distribution

    # Make a copy to avoid mutating the original DataFrame
    df = df.copy()

    # Remove any unnamed columns
    df = df.loc[:, ~df.columns.str.contains('^Unnamed')]

    # Normalise column names (strip whitespace)
    df.columns = [col.strip() for col in df.columns]

    # Drop duplicate rows to minimise bias caused by repeated entries
    df.drop_duplicates(inplace=True)

    # Identify target column
    possible_targets = [
        'label', 'Label', 'attack_type', 'Attack_type', 'class', 'Class', 'target'
    ]
    target_col = next((col for col in possible_targets if col in df.columns), None)

    if target_col is None:
        # Assume last column is the label/target
        target_col = df.columns[-1]
        df.rename(columns={target_col: 'label'}, inplace=True)
        target_col = 'label'

    # Store attack types
    attack_types = df[target_col].unique().tolist()

    # Separate features and target
    X = df.drop(columns=[target_col])
    y = df[target_col]

    # Record original class distribution for reporting and debugging
    class_distribution = Counter(y)

    # Encode categorical features & impute missing values
    label_encoders = {}
    for col in X.columns:
        if X[col].dtype == 'object':
            if X[col].isnull().any():
                X[col] = X[col].fillna(X[col].mode().iloc[0])
            le = LabelEncoder()
            X[col] = le.fit_transform(X[col].astype(str))
            label_encoders[col] = le
        else:
            if X[col].isnull().any():
                X[col] = X[col].fillna(X[col].median())

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

def _make_json_serializable(report):
    """Convert nested classification reports into JSON-serialisable primitives."""

    def convert_value(value):
        if isinstance(value, (np.floating, float)):
            return float(value)
        if isinstance(value, (np.integer, int)):
            return int(value)
        if isinstance(value, dict):
            return {k: convert_value(v) for k, v in value.items()}
        return value

    return {label: convert_value(metrics) for label, metrics in report.items()}


def train_models(X_resampled, X_test, y_resampled, y_test, X_train_original, y_train_original):
    """Train multiple ML models with regularisation and provide diagnostics"""
    results = {}

    rng = np.random.default_rng(42)

    # Random Forest
    print("Training Random Forest...")
    rf = RandomForestClassifier(
        n_estimators=200,
        max_depth=18,
        min_samples_leaf=4,
        class_weight='balanced_subsample',
        random_state=42,
        n_jobs=-1
    )
    rf.fit(X_resampled, y_resampled)
    rf_pred = rf.predict(X_test)
    rf_train_pred = rf.predict(X_train_original)
    models['random_forest'] = rf

    results['random_forest'] = {
        'accuracy': float(accuracy_score(y_test, rf_pred)),
        'train_accuracy': float(accuracy_score(y_train_original, rf_train_pred)),
        'confusion_matrix': confusion_matrix(y_test, rf_pred).tolist(),
        'classification_report': _make_json_serializable(
            classification_report(y_test, rf_pred, output_dict=True)
        )
    }

    # SVM (on a sample for speed)
    print("Training SVM...")
    sample_size = min(3000, len(X_resampled))
    indices = rng.choice(len(X_resampled), sample_size, replace=False)
    svm = SVC(kernel='rbf', class_weight='balanced', probability=True, random_state=42)
    svm.fit(X_resampled[indices], y_resampled[indices])
    svm_pred = svm.predict(X_test)
    svm_train_pred = svm.predict(X_train_original)
    models['svm'] = svm

    results['svm'] = {
        'accuracy': float(accuracy_score(y_test, svm_pred)),
        'train_accuracy': float(accuracy_score(y_train_original, svm_train_pred)),
        'confusion_matrix': confusion_matrix(y_test, svm_pred).tolist(),
        'classification_report': _make_json_serializable(
            classification_report(y_test, svm_pred, output_dict=True)
        ),
        'training_samples': int(sample_size)
    }

    # Neural Network
    print("Training Neural Network...")
    nn = MLPClassifier(
        hidden_layer_sizes=(128, 64),
        alpha=0.001,
        batch_size=128,
        learning_rate_init=0.001,
        early_stopping=True,
        validation_fraction=0.15,
        max_iter=120,
        random_state=42
    )
    nn.fit(X_resampled, y_resampled)
    nn_pred = nn.predict(X_test)
    nn_train_pred = nn.predict(X_train_original)
    models['neural_network'] = nn

    results['neural_network'] = {
        'accuracy': float(accuracy_score(y_test, nn_pred)),
        'train_accuracy': float(accuracy_score(y_train_original, nn_train_pred)),
        'confusion_matrix': confusion_matrix(y_test, nn_pred).tolist(),
        'classification_report': _make_json_serializable(
            classification_report(y_test, nn_pred, output_dict=True)
        )
    }

    # Cross-validation diagnostic for Random Forest to monitor overfitting tendencies
    try:
        # Limit the amount of data and folds used for cross-validation to keep
        # the training request responsive on modest hardware or managed hosting
        # environments with strict request timeouts.
        cv_sample_limit = 3000
        if len(X_train_original) > cv_sample_limit:
            subset_indices = rng.choice(len(X_train_original), cv_sample_limit, replace=False)
            X_cv = X_train_original[subset_indices]
            y_cv = y_train_original[subset_indices]
            cv_folds = 3
        else:
            X_cv = X_train_original
            y_cv = y_train_original
            cv_folds = 5

        # Guard against requesting more folds than available class members.
        if y_cv.size == 0:
            raise ValueError('No samples available for cross-validation')
        _, class_counts = np.unique(y_cv, return_counts=True)
        min_class_count = int(class_counts.min())
        if min_class_count < 2:
            raise ValueError('Not enough samples per class for cross-validation')
        if min_class_count < cv_folds:
            cv_folds = min_class_count

        cv = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=42)
        rf_cv_scores = cross_val_score(rf, X_cv, y_cv, cv=cv, n_jobs=-1)
        results['random_forest']['cross_val_accuracy'] = {
            'mean': float(np.mean(rf_cv_scores)),
            'std': float(np.std(rf_cv_scores))
        }
        if len(X_train_original) > cv_sample_limit:
            results['random_forest']['cross_val_accuracy']['sample_size'] = int(cv_sample_limit)
            results['random_forest']['cross_val_accuracy']['folds'] = int(cv_folds)
        else:
            results['random_forest']['cross_val_accuracy']['folds'] = int(cv_folds)
    except Exception as cv_error:
        results['random_forest']['cross_val_accuracy'] = {
            'error': str(cv_error)
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
            X, y, test_size=0.3, random_state=42, stratify=y
        )

        X_train_resampled, y_train_resampled = X_train, y_train

        if SMOTE is not None:
            try:
                smote = SMOTE(random_state=42)
                X_train_resampled, y_train_resampled = smote.fit_resample(X_train, y_train)
            except Exception as smote_error:
                print(f"SMOTE failed: {smote_error}. Proceeding without resampling.")

        # Train models
        results = train_models(
            X_train_resampled,
            X_test,
            y_train_resampled,
            y_test,
            X_train,
            y_train
        )
        
        # Save models
        with open('models/random_forest.pkl', 'wb') as f:
            pickle.dump(models['random_forest'], f)
        with open('models/svm.pkl', 'wb') as f:
            pickle.dump(models['svm'], f)
        with open('models/neural_network.pkl', 'wb') as f:
            pickle.dump(models['neural_network'], f)
        with open('models/scaler.pkl', 'wb') as f:
            pickle.dump(scaler, f)
        with open('models/label_encoders.pkl', 'wb') as f:
            pickle.dump(label_encoders, f)
        with open('models/feature_columns.pkl', 'wb') as f:
            pickle.dump(feature_columns, f)
        with open('models/attack_types.pkl', 'wb') as f:
            pickle.dump(attack_types, f)
        with open('models/class_distribution.json', 'w') as f:
            json.dump({str(k): int(v) for k, v in class_distribution.items()}, f)

        return jsonify({
            'success': True,
            'results': results,
            'class_distribution': {str(k): int(v) for k, v in class_distribution.items()},
            'feature_columns': feature_columns,
            'message': 'Models trained successfully with class balancing'
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
        confidence = None
        if hasattr(model, 'predict_proba'):
            prediction_proba = model.predict_proba(X_scaled)[0]
            confidence = float(np.max(prediction_proba))
        elif hasattr(model, 'decision_function'):
            decision = model.decision_function(X_scaled)
            if decision.ndim == 1:
                confidence = float(1 / (1 + np.exp(-abs(decision[0]))))
            else:
                confidence = float(np.max(decision))

        # Decode prediction
        attack_type = label_encoders['target'].inverse_transform([prediction])[0]

        result = {
            'prediction': attack_type,
            'is_attack': attack_type.lower() != 'normal',
            'confidence': confidence
        }
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def load_models():
    """Load saved models"""
    global models, scaler, label_encoders, feature_columns, attack_types, class_distribution

    try:
        with open('models/random_forest.pkl', 'rb') as f:
            models['random_forest'] = pickle.load(f)
        svm_path = 'models/svm.pkl'
        if os.path.exists(svm_path):
            with open(svm_path, 'rb') as f:
                models['svm'] = pickle.load(f)
        nn_path = 'models/neural_network.pkl'
        if os.path.exists(nn_path):
            with open(nn_path, 'rb') as f:
                models['neural_network'] = pickle.load(f)
        with open('models/scaler.pkl', 'rb') as f:
            scaler = pickle.load(f)
        with open('models/label_encoders.pkl', 'rb') as f:
            label_encoders = pickle.load(f)
        with open('models/feature_columns.pkl', 'rb') as f:
            feature_columns = pickle.load(f)
        with open('models/attack_types.pkl', 'rb') as f:
            attack_types = pickle.load(f)
        distribution_path = 'models/class_distribution.json'
        if os.path.exists(distribution_path):
            with open(distribution_path, 'r') as f:
                class_distribution = json.load(f)
    except FileNotFoundError:
        pass

@app.route('/status')
def status():
    """Get system status and any cached model metadata for manual predictions."""

    # Ensure previously trained artefacts are available after a restart.
    if not models or scaler is None or feature_columns is None:
        load_models()

    return jsonify({
        'models_trained': len(models) > 0,
        'available_models': sorted(models.keys()),
        'dataset_loaded': 'dataset_path' in session,
        'feature_columns': feature_columns or [],
        'attack_types': attack_types or [],
        'class_distribution': class_distribution or {}
    })

if __name__ == '__main__':
    app.run(debug=True, port=5000)