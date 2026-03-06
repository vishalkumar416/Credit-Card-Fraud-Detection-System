import streamlit as st
import mysql.connector
import firebase_admin
from firebase_admin import credentials, db, firestore
from google_auth_oauthlib.flow import Flow
import requests
import pickle
import numpy as np
import hashlib
import os
import zipfile
from dotenv import load_dotenv

# load env
load_dotenv()

st.set_page_config(page_title="Credit Card Fraud Detection", layout="centered")

# ui design
st.markdown("""
<style>

/* Hide Streamlit black toolbar / header */
[data-testid="stToolbar"],
[data-testid="stHeader"],
header[data-testid="stHeader"] {
display: none !important;
height: 0 !important;
}

[data-testid="stAppViewContainer"] {
background: linear-gradient(135deg,#5bc8d4 0%,#7b6fcf 40%,#c84b9e 75%,#d44b7b 100%);
min-height:100vh;
}

.block-container{
padding-top:3rem;
padding-bottom:3rem;
max-width:480px;
}

[data-testid="column"]:nth-child(2) > div:first-child{
background:white;
padding:48px 40px 40px;
border-radius:20px;
box-shadow:0 20px 60px rgba(0,0,0,0.2);
}

.app-title-box{
background: linear-gradient(135deg, #5bc8d4, #7b6fcf);
border-radius:14px;
padding:16px 24px;
text-align:center;
font-size:18px;
font-weight:800;
margin-bottom:28px;
color: white;
letter-spacing: 0.3px;
box-shadow: 0 4px 16px rgba(123,111,207,0.3);
}

.login-title{
text-align:center;
font-size:28px;
font-weight:800;
margin-bottom:28px;
}

.title-text{
text-align:center;
font-size:26px;
font-weight:800;
margin-bottom:24px;
}

/* Fix: Full-width gradient buttons */
div[data-testid="stButton"] > button{
width:100% !important;
height:48px;
border-radius:50px;
background:linear-gradient(90deg,#5bc8d4,#b44fc8,#d44b7b);
color:white;
font-weight:700;
border:none;
display:block;
}

div[data-testid="stButton"] > button:hover {
opacity:0.9;
transform: translateY(-1px);
transition: all 0.2s ease;
}

/* Google button styling */
.google-btn-wrapper {
margin: 8px 0;
width: 100%;
}

.google-btn {
display:flex;
align-items:center;
justify-content:center;
gap:10px;
width:100%;
height:48px;
border-radius:50px;
background:white;
border:2px solid #e0e0e0;
color:#3c4043;
font-weight:600;
font-size:15px;
font-family:inherit;
cursor:pointer;
text-decoration:none;
box-shadow:0 2px 8px rgba(0,0,0,0.08);
transition: all 0.2s ease;
box-sizing: border-box;
}

.google-btn:hover {
box-shadow:0 4px 16px rgba(0,0,0,0.15);
border-color:#c0c0c0;
text-decoration:none;
color:#3c4043;
}

.google-icon {
width:20px;
height:20px;
flex-shrink:0;
}

#MainMenu, footer{visibility:hidden;}

</style>
""", unsafe_allow_html=True)

# firebase init
firebase_config = {
"type": os.getenv("FIREBASE_TYPE"),
"project_id": os.getenv("FIREBASE_PROJECT_ID"),
"private_key_id": os.getenv("FIREBASE_PRIVATE_KEY_ID"),
"private_key": os.getenv("FIREBASE_PRIVATE_KEY").replace("\\n","\n"),
"client_email": os.getenv("FIREBASE_CLIENT_EMAIL"),
"client_id": os.getenv("FIREBASE_CLIENT_ID"),
"auth_uri": os.getenv("FIREBASE_AUTH_URI"),
"token_uri": os.getenv("FIREBASE_TOKEN_URI"),
"auth_provider_x509_cert_url": os.getenv("FIREBASE_AUTH_PROVIDER_X509_CERT_URL"),
"client_x509_cert_url": os.getenv("FIREBASE_CLIENT_X509_CERT_URL")
}

if not firebase_admin._apps:
    cred = credentials.Certificate(firebase_config)
    firebase_admin.initialize_app(cred,{
        "databaseURL": os.getenv("FIREBASE_DB_URL")
    })

firestore_db = firestore.client()

# MySQL Database
def connect_db():
    return mysql.connector.connect(
        host=os.getenv("MYSQLHOST"),
        user=os.getenv("MYSQLUSER"),
        password=os.getenv("MYSQLPASSWORD"),
        database=os.getenv("MYSQLDATABASE"),
        port=int(os.getenv("MYSQLPORT"))
    )

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Model loading
if not os.path.exists("model"):
    os.makedirs("model")
if not os.path.exists("model/model.pkl"):
    with zipfile.ZipFile("model.zip","r") as zip_ref:
        zip_ref.extractall("model")
model = pickle.load(open("model/model.pkl","rb"))
scaler = pickle.load(open("model/scaler.pkl","rb"))

# saving details of users
def save_user_everywhere(user_id,name,email,phone,role):

    db.reference("users/"+str(user_id)).set({
    "id":user_id,
    "name":name,
    "email":email,
    "phone":phone,
    "role":role
    })

    firestore_db.collection("users").document(str(user_id)).set({
    "id":user_id,
    "name":name,
    "email":email,
    "phone":phone,
    "role":role
    })

# login via google
def google_login_flow():
    os.environ["OAUTHLIB_INSECURE_TRANSPORT"]="1"
    flow=Flow.from_client_secrets_file(
    "firebase/credit-card-client_secret.json",
    scopes=["https://www.googleapis.com/auth/userinfo.email","openid"],
    redirect_uri="http://localhost:8501/"
    )
    if "code" in st.query_params:
        flow.fetch_token(code=st.query_params["code"])
        creds_google=flow.credentials
        user_info=requests.get(
        "https://www.googleapis.com/oauth2/v1/userinfo",
        params={"access_token":creds_google.token}
        ).json()
        email=user_info["email"]
        name=user_info.get("name",email.split("@")[0])
        conn=connect_db()
        cursor=conn.cursor()
        cursor.execute("SELECT id,name,phone FROM users WHERE email=%s",(email,))
        user=cursor.fetchone()
        if not user:
            cursor.execute(
            "INSERT INTO users(name,email,role) VALUES(%s,%s,%s)",
            (name,email,"user")
            )
            conn.commit()
            cursor.execute("SELECT id,name,phone FROM users WHERE email=%s",(email,))
            user=cursor.fetchone()
        user_id,name,phone=user
        save_user_everywhere(user_id,name,email,phone,"user")
        cursor.close()
        conn.close()

        st.session_state.user_id=user_id
        st.session_state.user_name=name
        st.query_params.clear()
        st.rerun()

    else:
        auth_url,_=flow.authorization_url(prompt="consent")

        # google button
        google_btn_html = f"""
        <div class="google-btn-wrapper">
            <a href="{auth_url}" class="google-btn">
                <svg class="google-icon" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                    <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/>
                    <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/>
                    <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05"/>
                    <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/>
                </svg>
                Continue with Google
            </a>
        </div>
        """
        st.markdown(google_btn_html, unsafe_allow_html=True)

# login page
def home():
    col1,col2,col3=st.columns([0.15,9.7,0.15])
    with col2:
        st.markdown("<div class='app-title-box'>💳 Credit Card Fraud Detection System</div>",unsafe_allow_html=True)
        st.markdown("<div class='login-title'>Login</div>",unsafe_allow_html=True)
        email=st.text_input("Username")
        password=st.text_input("Password",type="password")
        if st.button("LOGIN", use_container_width=True):
            conn=connect_db()
            cursor=conn.cursor()
            cursor.execute(
            "SELECT id,name FROM users WHERE email=%s AND password=%s",
            (email,hash_password(password))
            )
            user=cursor.fetchone()
            if user:
                st.session_state.user_id=user[0]
                st.session_state.user_name=user[1]
                st.rerun()
            else:
                st.error("Invalid credentials")
            cursor.close()
            conn.close()
        google_login_flow()
        if st.button("SIGN UP", use_container_width=True):
            st.session_state.page="register"
            st.rerun()
# register
def register():
    col1,col2,col3=st.columns([1,2,1])
    with col2:
        st.markdown("<div class='title-text'>Sign Up</div>",unsafe_allow_html=True)
        name=st.text_input("Full Name")
        email=st.text_input("Email")
        phone=st.text_input("Phone")
        password=st.text_input("Password",type="password")
        if st.button("CREATE ACCOUNT", use_container_width=True):
            conn=connect_db()
            cursor=conn.cursor()
            cursor.execute("SELECT id FROM users WHERE email=%s",(email,))
            if cursor.fetchone():
                st.error("User already exists")
            else:
                cursor.execute(
                "INSERT INTO users(name,email,phone,password,role) VALUES(%s,%s,%s,%s,%s)",
                (name,email,phone,hash_password(password),"user")
                )
                conn.commit()
                cursor.execute("SELECT id FROM users WHERE email=%s",(email,))
                user_id=cursor.fetchone()[0]
                save_user_everywhere(user_id,name,email,phone,"user")
                st.success("Account Created Successfully")
                st.session_state.page="home"
                st.rerun()
            cursor.close()
            conn.close()
        if st.button("Back to Login", use_container_width=True):
            st.session_state.page="home"
            st.rerun()
# dashboard
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
        amount_log = np.log1p(amount)
        input_data = np.array([[transaction_time, amount_log]])
        input_scaled = scaler.transform(input_data)
        probability = model.predict_proba(input_scaled)[0][1]
        if probability >= 0.75:
            final_label = "FRAUD"
        elif probability >= 0.40:
            final_label = "SUSPICIOUS"
        else:
            final_label = "SAFE"
        if amount > 200000 and (international == 1 or transaction_time < 4):
            final_label = "HIGH RISK FRAUD"
        elif amount > 100000 and international == 1:
            final_label = "FRAUD"
        risk_score = round(probability * 100, 1)

        conn = connect_db()
        cursor = conn.cursor()

        cursor.execute("""
        INSERT INTO reports
        (customer_id,amount,is_international,fraud_prediction,fraud_probability)
        VALUES(%s,%s,%s,%s,%s)
        """,(st.session_state.user_id,amount,international,final_label,risk_score))

        conn.commit()
        cursor.close()
        conn.close()

        st.success("Prediction: " + final_label)
        st.metric("Risk Score", str(risk_score) + "/100")

# routing
if "page" not in st.session_state:
    st.session_state.page="home"
if st.session_state.get("user_id"):
    dashboard()
elif "code" in st.query_params:
    google_login_flow()
elif st.session_state.page=="register":
    register()
else:
    home()