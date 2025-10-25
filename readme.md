# 🛡️ Network Attack Detection System

## Project Structure

```
network-attack-detection/
│
├── app.py                          # Main Flask application
├── requirements.txt                # Python dependencies
├── templates/
│   └── index.html                  # Main web interface
├── uploads/                        # Uploaded datasets (created automatically)
├── models/                         # Saved ML models (created automatically)
└── README.md                       # This file
```

## Quick Start Guide

### 1. Install Dependencies

```bash
# Create virtual environment (recommended)
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On Mac/Linux:
source venv/bin/activate

# Install required packages
pip install -r requirements.txt
```

### 2. Create requirements.txt

Create a file named `requirements.txt` with the following content:

```
Flask==3.0.0
pandas==2.1.4
numpy==1.26.2
scikit-learn==1.3.2
werkzeug==3.0.1
```

### 3. Project Setup

Create the following directory structure:

```bash
mkdir network-attack-detection
cd network-attack-detection
mkdir templates
```

- Save `app.py` in the root directory
- Save `index.html` in the `templates/` folder
- Create `requirements.txt` in the root directory

### 4. Run the Application

```bash
python app.py
```

The application will start on `http://localhost:5000`

## Using the System

### Step 1: Upload Dataset

1. Download the NSL-KDD dataset or use any network traffic CSV
2. Drag and drop the CSV file or click "Browse Files"
3. Wait for upload confirmation

**NSL-KDD Dataset Sources:**
- [NSL-KDD Dataset - Kaggle](https://www.kaggle.com/datasets/hassan06/nslkdd)
- [NSL-KDD Dataset - UNB](https://www.unb.ca/cic/datasets/nsl.html)

### Step 2: Train Models

1. Click the "Train Models" button
2. Wait for training to complete (may take 2-5 minutes)
3. View accuracy and confusion matrices for:
   - Random Forest
   - Support Vector Machine (SVM)
   - Neural Network

### Step 3: Detect Attacks

1. Enter network traffic parameters in the form
2. Click "Detect Attack"
3. View the prediction results:
   - ✅ Normal Traffic (green)
   - ⚠️ Attack Detected (red) with attack type

## Sample Dataset Format

Your CSV should contain columns like:

```csv
duration,protocol_type,service,flag,src_bytes,dst_bytes,count,srv_count,label
0,tcp,http,SF,215,45076,1,1,normal
0,tcp,http,SF,162,4528,8,8,normal
0,tcp,http,SF,236,1228,1,1,neptune
```

**Common Attack Types:**
- **normal** - Normal traffic
- **DoS** - Denial of Service (neptune, smurf, pod, etc.)
- **Probe** - Surveillance (portsweep, ipsweep, nmap, etc.)
- **R2L** - Remote to Local (warezclient, guess_passwd, etc.)
- **U2R** - User to Root (buffer_overflow, rootkit, etc.)

## Features

### Machine Learning Models
- **Random Forest**: Ensemble learning with 100 decision trees
- **SVM**: Support Vector Machine with RBF kernel
- **Neural Network**: Multi-layer perceptron with 100-50 hidden layers

### Preprocessing
- Automatic categorical encoding
- Feature scaling with StandardScaler
- Label encoding for target classes
- Handles missing values

### Web Interface
- Modern, responsive design
- Real-time status dashboard
- Drag-and-drop file upload
- Interactive prediction form
- Visual results display

## API Endpoints

### Upload Dataset
```
POST /upload
Content-Type: multipart/form-data
Body: file (CSV file)

Response:
{
  "success": true,
  "rows": 25000,
  "columns": 42,
  "filename": "dataset.csv"
}
```

### Train Models
```
POST /train

Response:
{
  "success": true,
  "results": {
    "random_forest": {
      "accuracy": 0.95,
      "confusion_matrix": [[...], [...]]
    },
    ...
  }
}
```

### Make Prediction
```
POST /predict
Content-Type: application/json
Body:
{
  "model": "random_forest",
  "features": {
    "duration": 0,
    "protocol_type": "tcp",
    "service": "http",
    ...
  }
}

Response:
{
  "prediction": "normal",
  "is_attack": false,
  "confidence": 0.98
}
```

### Check Status
```
GET /status

Response:
{
  "models_trained": true,
  "available_models": ["random_forest", "svm", "neural_network"],
  "dataset_loaded": true
}
```

## Troubleshooting

### Issue: Models taking too long to train
**Solution**: The dataset might be very large. SVM is trained on a sample of 5000 records to speed up the process.

### Issue: File upload fails
**Solution**: 
- Check file size (max 16MB)
- Ensure the file is a valid CSV
- Check file permissions

### Issue: Prediction errors
**Solution**:
- Ensure models are trained before prediction
- Check that input features match training data format
- Verify all required fields are filled

### Issue: Port 5000 already in use
**Solution**: Change the port in `app.py`:
```python
app.run(debug=True, port=5001)  # Change to any available port
```

## Performance Optimization

For better performance:
1. Use smaller datasets for initial testing
2. Reduce Random Forest estimators if training is slow
3. Adjust Neural Network max_iter parameter
4. Use SVM sample size parameter to control training time

## Security Notes

⚠️ **Important**: This is a demonstration project.

For production use:
- Change the Flask secret key
- Add user authentication
- Implement rate limiting
- Add input validation
- Use HTTPS
- Sanitize file uploads
- Add CSRF protection

## Technologies Used

- **Backend**: Python, Flask
- **ML Libraries**: scikit-learn, pandas, numpy
- **Frontend**: HTML5, CSS3, JavaScript (Vanilla)
- **Data Processing**: pandas, LabelEncoder, StandardScaler
- **Models**: Random Forest, SVM, Neural Network

## Project Demo Flow

1. **Upload** → Upload NSL-KDD dataset (CSV)
2. **Process** → System preprocesses and encodes data
3. **Train** → Train 3 ML models simultaneously
4. **Evaluate** → View accuracy and confusion matrices
5. **Predict** → Input new network traffic parameters
6. **Detect** → Get instant attack classification

## Future Enhancements

- [ ] Add more ML algorithms (XGBoost, LightGBM)
- [ ] Real-time packet capture integration
- [ ] Interactive visualization charts (D3.js)
- [ ] Model performance comparison
- [ ] Export predictions to CSV
- [ ] User authentication system
- [ ] API rate limiting
- [ ] Detailed attack analysis reports
- [ ] Model retraining scheduler
- [ ] Multi-file batch prediction

## License

This project is for educational purposes.

## Contact & Support

For questions or issues, refer to:
- Flask Documentation: https://flask.palletsprojects.com/
- scikit-learn Documentation: https://scikit-learn.org/
- NSL-KDD Dataset Info: https://www.unb.ca/cic/datasets/nsl.html

---

**Built with ❤️ for Network Security**