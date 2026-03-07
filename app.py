import streamlit as st
import firebase_admin
from firebase_admin import credentials, firestore
from google_auth_oauthlib.flow import Flow
import requests
import pickle
import numpy as np
import hashlib
import os
import zipfile
from dotenv import load_dotenv
from datetime import datetime

load_dotenv()

st.set_page_config(page_title="Credit Card Fraud Detection", layout="centered")

# page styling
st.markdown("""
<style>
[data-testid="stToolbar"],[data-testid="stHeader"]{display:none;}
[data-testid="stAppViewContainer"]{
background:linear-gradient(135deg,#5bc8d4,#7b6fcf,#c84b9e,#d44b7b);
}
.block-container{max-width:480px;padding-top:3rem;}
.app-title-box{
background:linear-gradient(135deg,#5bc8d4,#7b6fcf);
padding:16px;border-radius:12px;color:white;font-weight:700;text-align:center;
margin-bottom:25px;
}
div[data-testid="stButton"]>button{
width:100%;height:48px;border-radius:40px;border:none;
background:linear-gradient(90deg,#5bc8d4,#b44fc8,#d44b7b);
color:white;font-weight:700;font-size:15px;
}
.google-btn{
display:flex;align-items:center;justify-content:center;
gap:10px;width:100%;height:48px;border-radius:40px;
background:white;border:2px solid #e0e0e0;
text-decoration:none;color:#333;font-weight:600;font-size:15px;
box-sizing:border-box;margin-top:4px;margin-bottom:4px;
}
.google-icon{width:20px;height:20px;flex-shrink:0;}
</style>
""", unsafe_allow_html=True)

# connect firebase
firebase_config = {
    "type": os.getenv("FIREBASE_TYPE",""),
    "project_id": os.getenv("FIREBASE_PROJECT_ID"),
    "private_key_id": os.getenv("FIREBASE_PRIVATE_KEY_ID"),
    "private_key": os.getenv("FIREBASE_PRIVATE_KEY").replace("\\n", "\n"),
    "client_email": os.getenv("FIREBASE_CLIENT_EMAIL"),
    "client_id": os.getenv("FIREBASE_CLIENT_ID"),
    "auth_uri": os.getenv("FIREBASE_AUTH_URI"),
    "token_uri": os.getenv("FIREBASE_TOKEN_URI"),
    "auth_provider_x509_cert_url": os.getenv("FIREBASE_AUTH_PROVIDER_X509_CERT_URL"),
    "client_x509_cert_url": os.getenv("FIREBASE_CLIENT_X509_CERT_URL")
}

if not firebase_admin._apps:
    cred = credentials.Certificate(firebase_config)
    firebase_admin.initialize_app(cred)

firestore_db = firestore.client()

# load model and scaler
if not os.path.exists("model"):
    os.makedirs("model")

if not os.path.exists("model/model.pkl"):
    with zipfile.ZipFile("model.zip", "r") as zip_ref:
        zip_ref.extractall("model")

model = pickle.load(open("model/model.pkl", "rb"))
scaler = pickle.load(open("model/scaler.pkl", "rb"))

# hash password before saving
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# get next user_id by counting existing users (auto-increment, no counters collection)
def get_next_user_id():
    all_users = firestore_db.collection("users").get()
    return len(all_users) + 1

# google login
def google_login_flow():
    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
    flow = Flow.from_client_secrets_file(
        "firebase/credit-card-client_secret.json",
        scopes=["https://www.googleapis.com/auth/userinfo.email", "openid"],
        redirect_uri="http://localhost:8501/"
    )

    if "code" in st.query_params:
        # get user info from google
        flow.fetch_token(code=st.query_params["code"])
        creds_google = flow.credentials
        user_info = requests.get(
            "https://www.googleapis.com/oauth2/v1/userinfo",
            params={"access_token": creds_google.token}
        ).json()

        email = user_info["email"]
        name = user_info.get("name", email.split("@")[0])
        users = firestore_db.collection("users").where("email", "==", email).get()

        if users:
            # existing user, just grab their id and user_id
            user_id = users[0].id
            user_name = users[0].to_dict()["name"]
            user_int_id = users[0].to_dict().get("user_id")
        else:
            # new user, assign next user_id as primary key
            user_int_id = get_next_user_id()
            doc = firestore_db.collection("users").add({
                "user_id": user_int_id,
                "name": name,
                "email": email,
                "phone": "",
                "password": "",
                "role": "user",
                "created_at": datetime.utcnow()
            })
            user_id = doc[1].id
            user_name = name

        st.session_state.user_id = user_id
        st.session_state.user_name = user_name
        st.session_state.user_int_id = user_int_id
        st.query_params.clear()
        st.rerun()

    else:
        # show google login button
        auth_url, _ = flow.authorization_url(prompt="consent")
        st.markdown(f"""
        <a href="{auth_url}" class="google-btn">
        <svg class="google-icon" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
          <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
          <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
          <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l3.66-2.84z"/>
          <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
        </svg>
        Continue with Google
        </a>
        """, unsafe_allow_html=True)

# login page
def home():
    st.markdown("<div class='app-title-box'>💳 Credit Card Fraud Detection</div>", unsafe_allow_html=True)
    email = st.text_input("Email")
    password = st.text_input("Password", type="password")

    if st.button("LOGIN", use_container_width=True):
        users = firestore_db.collection("users").where("email", "==", email).get()
        if users:
            user = users[0].to_dict()
            if user.get("password") == hash_password(password):
                st.session_state.user_id = users[0].id
                st.session_state.user_name = user["name"]
                st.session_state.user_int_id = user.get("user_id")
                st.rerun()
            else:
                st.error("Invalid credentials")
        else:
            st.error("User not found")

    google_login_flow()

    if st.button("SIGN UP", use_container_width=True):
        st.session_state.page = "register"
        st.rerun()

# register page
def register():
    st.title("Sign Up")
    name = st.text_input("Full Name")
    email = st.text_input("Email")
    phone = st.text_input("Phone")
    password = st.text_input("Password", type="password")

    if st.button("CREATE ACCOUNT"):
        users = firestore_db.collection("users").where("email", "==", email).get()
        if users:
            st.error("User already exists")
        else:
            user_int_id = get_next_user_id()
            doc = firestore_db.collection("users").add({
                "user_id": user_int_id,
                "name": name,
                "email": email,
                "phone": phone,
                "password": hash_password(password),
                "role": "user",
                "created_at": datetime.utcnow()
            })
            st.success("Account Created Successfully")
            st.session_state.page = "home"
            st.rerun()

# dashboard - fraud prediction page
def dashboard():
    st.title("Fraud Detection Dashboard")
    st.sidebar.success("Welcome " + st.session_state.user_name)

    if st.sidebar.button("Logout"):
        st.session_state.clear()
        st.rerun()

    transaction_time = st.number_input("Transaction Time", min_value=0, step=1)
    amount = st.number_input("Amount", min_value=0, step=1)
    international = st.selectbox("International", [0, 1])

    if st.button("Predict", use_container_width=True):
        # prepare input and run model
        amount_log = np.log1p(amount)
        input_data = np.array([[transaction_time, amount_log]])
        input_scaled = scaler.transform(input_data)
        probability = model.predict_proba(input_scaled)[0][1]

        # ml based label
        if probability >= 0.75:
            final_label = "FRAUD"
        elif probability >= 0.40:
            final_label = "SUSPICIOUS"
        else:
            final_label = "SAFE"

        # rule based override for high risk cases
        if amount > 200000 and (international == 1 or transaction_time < 4):
            final_label = "HIGH RISK FRAUD"
        elif amount > 100000 and international == 1:
            final_label = "FRAUD"

        risk_score = round(probability * 100, 1)

        # save result to firestore
        firestore_db.collection("reports").add({
            "user_id": st.session_state.get("user_int_id"),
            "amount": amount,
            "is_international": international,
            "fraud_prediction": final_label,
            "fraud_probability": risk_score,
            "created_at": datetime.utcnow()
        })

        st.success("Prediction: " + final_label)
        st.metric("Risk Score", str(risk_score) + "/100")

# routing
if "page" not in st.session_state:
    st.session_state.page = "home"

if st.session_state.get("user_id"):
    dashboard()
elif "code" in st.query_params:
    google_login_flow()
elif st.session_state.page == "register":
    register()
else:
    home()
