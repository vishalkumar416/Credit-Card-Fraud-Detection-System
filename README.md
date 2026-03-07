# Credit Card Fraud Detection System

## 📋 Overview
A comprehensive web-based fraud detection system that uses machine learning combined with rule-based heuristics to identify and flag potentially fraudulent credit card transactions. The system provides real-time predictions with a user-friendly interface and secure authentication mechanisms.

## ✨ Features
- **ML-Based Fraud Detection**: Uses trained machine learning model for probability-based predictions
- **Rule-Based Override**: Implements business rules for high-risk transaction scenarios
- **User Authentication**: Supports both email/password login and Google OAuth
- **Real-Time Predictions**: Instant fraud assessment with risk scoring
- **Transaction History**: All predictions are logged and stored for review
- **Secure Database**: Firebase Firestore backend for secure data storage
- **Responsive UI**: Beautiful, gradient-based interface built with Streamlit

## 🛠️ Tech Stack
- **Frontend**: Streamlit (Python)
- **Backend**: Python with Streamlit
- **Database**: Firebase Firestore
- **Authentication**: Firebase Authentication + Google OAuth
- **ML Framework**: Scikit-learn
- **Additional Libraries**:
  - NumPy for numerical computations
  - Requests for HTTP calls
  - Python-dotenv for environment variables

## 📦 Installation

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)
- Firebase project credentials
- Google OAuth credentials (optional, for Google login)

### Steps
1. Clone the repository:
```bash
git clone https://github.com/vishalkumar416/Credit-Card-Fraud-Detection-System.git
cd Credit-Card-Fraud-Detection-System
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Set up environment variables:
Create a `.env` file in the project root and add your Firebase credentials:
```
FIREBASE_TYPE=service_account
FIREBASE_PROJECT_ID=your_project_id
FIREBASE_PRIVATE_KEY_ID=your_private_key_id
FIREBASE_PRIVATE_KEY=your_private_key
FIREBASE_CLIENT_EMAIL=your_client_email
FIREBASE_CLIENT_ID=your_client_id
FIREBASE_AUTH_URI=https://accounts.google.com/o/oauth2/auth
FIREBASE_TOKEN_URI=https://oauth2.googleapis.com/token
FIREBASE_AUTH_PROVIDER_X509_CERT_URL=https://www.googleapis.com/oauth2/v1/certs
FIREBASE_CLIENT_X509_CERT_URL=your_cert_url
```

## 🚀 How to Run

1. Ensure all dependencies are installed and `.env` file is configured

2. Run the Streamlit application:
```bash
streamlit run app.py
```

3. Open your browser and navigate to:
```
http://localhost:8501
```

4. Log in using:
   - Email and password, OR
   - Google OAuth button

## 📖 Usage

### Login/Registration
- **Login**: Enter your email and password
- **Sign Up**: Create a new account with name, email, phone, and password
- **Google Login**: Click "Continue with Google" for quick authentication

### Fraud Detection
1. Navigate to the Fraud Detection Dashboard after logging in
2. Enter transaction details:
   - **Transaction Time**: Time of the transaction
   - **Amount**: Transaction amount
   - **International**: Select 0 (domestic) or 1 (international)
3. Click "Predict" to get the fraud assessment
4. View results:
   - Prediction label (SAFE, SUSPICIOUS, FRAUD, HIGH RISK FRAUD)
   - Risk Score (0-100)

## 🏗️ Project Structure

```
Credit-Card-Fraud-Detection-System/
├── app.py                          # Main Streamlit application
├── requirements.txt                # Python dependencies
├── model.zip                       # Compressed ML model files
├── model/                          # (Auto-generated) Extracted model
│   ├── model.pkl                   # Trained ML model
│   └── scaler.pkl                  # Feature scaler
├── database/                       # Database configurations
├── firebase/                       # Firebase configurations
│   └── credit-card-client_secret.json  # Google OAuth credentials
└── .env                            # Environment variables (not in repo)
```

## 🤖 Model Details

### Model Type
Trained machine learning classifier (likely Logistic Regression or similar)

### Input Features
- Transaction Time (numerical)
- Amount (numerical, log-transformed)
- International Flag (binary: 0 or 1)

### Output
- Fraud Probability (0-1)
- Prediction Label based on probability thresholds and business rules

### Prediction Thresholds
- **SAFE**: Probability < 0.40
- **SUSPICIOUS**: Probability between 0.40 - 0.75
- **FRAUD**: Probability >= 0.75

### Rule-Based Overrides
- **HIGH RISK FRAUD**: Amount > 200,000 AND (International OR Transaction Time < 4 hours)
- **FRAUD**: Amount > 100,000 AND International

## 🔐 Authentication

### Email/Password Login
- User credentials stored securely in Firebase with SHA-256 hashed passwords
- Email-based user lookup
- Session management via Streamlit

### Google OAuth
- Secure third-party authentication via Google
- Automatic user creation on first login
- No password storage for OAuth users

### Session Management
- User information stored in Streamlit session state
- User ID and profile information retrieved from Firebase
- Logout clears session and returns to login page

## 📊 Data Storage

All transaction predictions are stored in Firebase Firestore with the following information:
- User ID
- Transaction Amount
- International Status
- Fraud Prediction
- Fraud Probability/Risk Score
- Timestamp

## 🔧 Troubleshooting

### Firebase Connection Issues
- Verify `.env` file has correct Firebase credentials
- Check Firebase project has Firestore enabled
- Ensure Firebase rules allow read/write access

### Model Loading Issues
- Ensure `model.zip` is in the project root
- Model files will be auto-extracted on first run
- Check file permissions in the model directory

### Google OAuth Issues
- Verify `credit-card-client_secret.json` exists in firebase/ directory
- Check OAuth redirect URI matches your deployment URL
- For local development, OAUTHLIB_INSECURE_TRANSPORT is set to 1

## 📝 License
This project is open source and available under the MIT License.

## 👨‍💻 Author
Vishal Kumar

## 🤝 Contributing
Contributions are welcome! Feel free to fork this repository and submit pull requests.