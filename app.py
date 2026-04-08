import streamlit as st
import mysql.connector
import firebase_admin
from firebase_admin import credentials, firestore
from google_auth_oauthlib.flow import Flow
import requests
import pickle
import numpy as np
import hashlib
import os
import zipfile
import stripe
from dotenv import load_dotenv
from datetime import datetime
import re
import phonenumbers
from email_validator import validate_email, EmailNotValidError

load_dotenv()

# --- CONFIGURATION & ENV CHECK ---
def check_required_env():
    required_keys = [
        "STRIPE_SECRET_KEY", "FIREBASE_TYPE", "FIREBASE_PROJECT_ID", 
        "FIREBASE_PRIVATE_KEY_ID", "FIREBASE_PRIVATE_KEY", "FIREBASE_CLIENT_EMAIL",
        "DB_HOST", "DB_USER", "DB_NAME"
    ]
    missing = [key for key in required_keys if not os.getenv(key)]
    return missing

missing_vars = check_required_env()

st.set_page_config(page_title="Credit Card Fraud Detection", layout="centered")

# Determine Base URL for redirects
# On Render, we can use the environment variable RENDER_EXTERNAL_URL if set, or default to localhost
BASE_URL = os.getenv("RENDER_EXTERNAL_URL", "http://localhost:8501").rstrip("/") + "/"


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

# Show error if env vars are missing
if missing_vars:
    st.error(f"⚠️ Missing Environment Variables: {', '.join(missing_vars)}")
    st.info("Please set these variables in your Render Dashboard or .env file.")
    if not os.getenv("RENDER_EXTERNAL_URL"): # Only stop if local and missing, or maybe just warn on Render
        st.warning("The application may not function correctly.")

stripe.api_key = os.getenv("STRIPE_SECRET_KEY")

# connect firebase
firebase_key = os.getenv("FIREBASE_PRIVATE_KEY", "")
if firebase_key:
    firebase_key = firebase_key.replace("\\n", "\n")

firebase_config = {
    "type": os.getenv("FIREBASE_TYPE",""),
    "project_id": os.getenv("FIREBASE_PROJECT_ID"),
    "private_key_id": os.getenv("FIREBASE_PRIVATE_KEY_ID"),
    "private_key": firebase_key,
    "client_email": os.getenv("FIREBASE_CLIENT_EMAIL"),
    "client_id": os.getenv("FIREBASE_CLIENT_ID"),
    "auth_uri": os.getenv("FIREBASE_AUTH_URI"),
    "token_uri": os.getenv("FIREBASE_TOKEN_URI"),
    "auth_provider_x509_cert_url": os.getenv("FIREBASE_AUTH_PROVIDER_X509_CERT_URL"),
    "client_x509_cert_url": os.getenv("FIREBASE_CLIENT_X509_CERT_URL")
}

try:
    if not firebase_admin._apps:
        cred = credentials.Certificate(firebase_config)
        firebase_admin.initialize_app(cred)
    firestore_db = firestore.client()
except Exception as e:
    st.error(f"Firebase Initialization Error: {e}")
    firestore_db = None


# load model and scaler
if not os.path.exists("model"):
    os.makedirs("model")

if not os.path.exists("model/model.pkl"):
    with zipfile.ZipFile("model.zip", "r") as zip_ref:
        zip_ref.extractall("model")

model = pickle.load(open("model/model.pkl", "rb"))
scaler = pickle.load(open("model/scaler.pkl", "rb"))

def is_luhn_valid(card_num):
    card_num = str(card_num).replace(" ", "").replace("-", "")
    if not card_num.isdigit():
        return False
    total = 0
    reverse_digits = card_num[::-1]
    for i, digit in enumerate(reverse_digits):
        n = int(digit)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0

def is_upi_valid(upi_id):
    pattern = r"^[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}$"
    return bool(re.match(pattern, upi_id))

def is_phone_valid(phone):
    try:
        if len(phone) == 10 and phone.isdigit():
            phone = "+91" + phone
        elif not phone.startswith("+"):
            phone = "+" + phone
        parsed = phonenumbers.parse(phone)
        return phonenumbers.is_valid_number(parsed)
    except phonenumbers.NumberParseException:
        return False

def check_email_domain(email):
    disposable_domains = ['mailinator.com', '10minutemail.com', 'guerrillamail.com', 'tempmail.com', 'yopmail.com']
    try:
        valid = validate_email(email)
        domain = valid.domain
        if domain in disposable_domains:
            return False, "Disposable domain detected"
        return True, "Valid email"
    except EmailNotValidError as e:
        return False, str(e)

# hash password before saving
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def get_db_connection():
    try:
        conn = mysql.connector.connect(
            host=os.getenv("DB_HOST", "localhost"),
            user=os.getenv("DB_USER", "root"),
            password=os.getenv("DB_PASSWORD", ""),
            database=os.getenv("DB_NAME", "credit_card_db"),
            autocommit=True
        )
        return conn
    except mysql.connector.Error as err:
        st.error(f"Error connecting to MySQL: {err}")
        return None

def init_db():
    try:
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS payments (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT,
                    stripe_session_id VARCHAR(255),
                    amount DECIMAL(10,2),
                    status VARCHAR(50),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()
            cursor.close()
            conn.close()
    except Exception as e:
        st.warning(f"Database initialization delayed or failed: {e}")

init_db()


def check_payment_status():
    if "session_id" in st.query_params:
        session_id = st.query_params["session_id"]
        try:
            session = stripe.checkout.Session.retrieve(session_id)
            if session.payment_status == "paid":
                # client_reference_id contains user_int_id
                user_int_id = int(session.client_reference_id) if session.client_reference_id else None
                conn = get_db_connection()
                if conn:
                    cursor = conn.cursor()
                    cursor.execute("SELECT * FROM payments WHERE stripe_session_id = %s", (session_id,))
                    if not cursor.fetchone():
                        cursor.execute("INSERT INTO payments (user_id, stripe_session_id, amount, status) VALUES (%s, %s, %s, %s)",
                                       (user_int_id, session_id, session.amount_total / 100.0, "paid"))
                        conn.commit()
                        firestore_db.collection("payments").add({
                            "user_id": user_int_id,
                            "stripe_session_id": session_id,
                            "amount": session.amount_total / 100.0,
                            "status": "paid",
                            "created_at": datetime.utcnow()
                        })
                    cursor.close()
                    conn.close()
                st.session_state.payment_success = True
        except Exception as e:
            st.error(f"Error verifying payment: {e}")
        
        st.query_params.clear()

# google login
def google_login_flow():
    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
    
    # Ensure redirect_uri matches BASE_URL
    flow = Flow.from_client_secrets_file(
        "firebase/credit-card-client_secret.json",
        scopes=["https://www.googleapis.com/auth/userinfo.email", "openid"],
        redirect_uri=BASE_URL
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
            # new user, insert into MySQL first to get id
            conn = get_db_connection()
            if conn:
                cursor = conn.cursor()
                sql = "INSERT INTO users (name, email, phone, password, role) VALUES (%s, %s, %s, %s, %s)"
                val = (name, email, "", "", "user")
                cursor.execute(sql, val)
                user_int_id = cursor.lastrowid
                conn.commit()
                cursor.close()
                conn.close()
            else:
                st.error("Could not connect to database")
                st.stop()

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
            conn = get_db_connection()
            if conn:
                cursor = conn.cursor()
                sql = "INSERT INTO users (name, email, phone, password, role) VALUES (%s, %s, %s, %s, %s)"
                val = (name, email, phone, hash_password(password), "user")
                cursor.execute(sql, val)
                user_int_id = cursor.lastrowid
                conn.commit()
                cursor.close()
                conn.close()
            else:
                st.error("Could not connect to database")
                st.stop()

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

    if st.sidebar.button("Prediction History"):
        st.session_state.view_history = True

    if st.sidebar.button("Logout"):
        st.session_state.clear()
        st.rerun()

    if st.session_state.get("view_history"):
        st.subheader("All Users Prediction History")
        if st.button("Back to Prediction"):
            st.session_state.view_history = False
            st.rerun()
            
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor(dictionary=True)
            sql = "SELECT customer_id as user_id, amount, is_international as international, fraud_prediction as prediction, fraud_probability as risk_score, created_at FROM reports ORDER BY created_at DESC"
            cursor.execute(sql)
            history_data = cursor.fetchall()
            cursor.close()
            conn.close()

            if history_data:
                st.dataframe(history_data, use_container_width=True)
            else:
                st.info("No prediction history found.")
        else:
            st.error("Could not connect to database")
    else:
        # Check prediction limit and payment
        can_predict = False
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM reports WHERE customer_id = %s", (st.session_state.get("user_int_id"),))
            pred_count = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM payments WHERE user_id = %s AND status = 'paid'", (st.session_state.get("user_int_id"),))
            payment_count = cursor.fetchone()[0]
            cursor.close()
            conn.close()
            
            if payment_count > 0 or pred_count < 3:
                can_predict = True

        if not can_predict:
            st.warning("You have reached the free limit of 3 predictions. Please subscribe to continue.")
            st.markdown("### Choose a Subscription Plan")
            col1, col2, col3 = st.columns(3)
            
            plans = [
                {"name": "Weekly Plan", "price": 7, "col": col1},
                {"name": "Monthly Plan", "price": 25, "col": col2},
                {"name": "Yearly Plan", "price": 269, "col": col3}
            ]
            
            for plan in plans:
                with plan["col"]:
                    st.info(f"**{plan['name']}**  \n${plan['price']}")
                    try:
                        checkout_session = stripe.checkout.Session.create(
                            payment_method_types=['card'],
                            line_items=[{
                                'price_data': {
                                    'currency': 'usd',
                                    'product_data': {
                                        'name': f'Fraud Detection {plan["name"]}',
                                    },
                                    'unit_amount': plan['price'] * 100,
                                },
                                'quantity': 1,
                            }],
                            mode='payment',
                            success_url=f'{BASE_URL}?session_id={{CHECKOUT_SESSION_ID}}',
                            cancel_url=BASE_URL,
                            client_reference_id=str(st.session_state.get("user_int_id"))

                        )
                        st.markdown(f'<a href="{checkout_session.url}" target="_self" style="text-decoration:none;"><button style="width:100%;height:40px;border-radius:20px;border:none;background:linear-gradient(90deg,#5bc8d4,#b44fc8);color:white;font-weight:700;font-size:14px;cursor:pointer;">Subscribe</button></a>', unsafe_allow_html=True)
                    except Exception as e:
                        st.error(f"Error initiating payment: {e}")
            st.stop()
            
        st.subheader("Transaction & Verification Details")
        col1, col2 = st.columns(2)
        with col1:
            transaction_time = st.number_input("Transaction Time (in hrs)", min_value=0, step=1)
            amount = st.number_input("Amount", min_value=0, step=1)
            international = st.selectbox("International", [0, 1])
        with col2:
            st.markdown("**(New) Verification Info**")
            credit_card = st.text_input("Credit Card Number (optional)")
            phone = st.text_input("Customer Phone (optional)", placeholder="e.g. +91XXXXXXXXXX")
            upi = st.text_input("UPI ID (optional)", placeholder="user@bank")
            email = st.text_input("Customer Email (optional)")
            credit_score = st.number_input("Credit Score (0 if unknown)", min_value=0, max_value=900, value=0, step=1)

        if st.button("Predict", use_container_width=True):
            # prepare input and run ML model
            amount_log = np.log1p(amount)
            input_data = np.array([[transaction_time, amount_log]])
            input_scaled = scaler.transform(input_data)
            probability = model.predict_proba(input_scaled)[0][1]

            risk_score = float(probability * 100)
            
            # --- REAL WORLD VALIDATION LOGIC ---
            validation_messages = []
            
            if credit_card:
                if not is_luhn_valid(credit_card):
                    risk_score += 40
                    validation_messages.append("❌ Invalid Credit Card (Luhn check failed)")
                else:
                    validation_messages.append("✅ Credit Card Valid (Luhn check passed)")

            if phone:
                if not is_phone_valid(phone):
                    risk_score += 20
                    validation_messages.append("❌ Invalid Phone Number format or telecom info")
                else:
                    validation_messages.append("✅ Phone Number Valid")

            if upi:
                if not is_upi_valid(upi):
                    risk_score += 25
                    validation_messages.append("❌ Invalid UPI ID format")
                else:
                    validation_messages.append("✅ UPI ID format valid")

            if email:
                is_valid, msg = check_email_domain(email)
                if not is_valid:
                    risk_score += 30
                    validation_messages.append(f"❌ Email Risk: {msg}")
                else:
                    validation_messages.append("✅ Email Valid")
                    
            if credit_score > 0:
                if credit_score < 550:
                    risk_score += 20
                    validation_messages.append(f"❌ Low Credit Score ({credit_score}): Risk Increased")
                elif credit_score < 650:
                    risk_score += 10
                    validation_messages.append(f"⚠️ Fair Credit Score ({credit_score}): Slight Risk")
                else:
                    risk_score -= 10
                    validation_messages.append(f"✅ Good Credit Score ({credit_score}): Risk Decreased")
                    
            # Ensure risk score is capped at 0 and 100
            risk_score = max(0.0, min(risk_score, 100.0))

            # Assign Label based on new Risk Score
            if risk_score >= 80:
                final_label = "HIGH RISK FRAUD"
            elif risk_score >= 60:
                final_label = "FRAUD"
            elif risk_score >= 40:
                final_label = "SUSPICIOUS"
            else:
                final_label = "SAFE"

            # rule based override for extreme numeric values (legacy)
            if amount > 200000 and (international == 1 or transaction_time < 4):
                final_label = "HIGH RISK FRAUD"
                risk_score = max(risk_score, 95.0)
            elif amount > 100000 and international == 1:
                final_label = "FRAUD"
                risk_score = max(risk_score, 85.0)
            
            risk_score = round(risk_score, 1)

            # Display messages
            with st.expander("Validation Details (Real-World Checks)", expanded=True):
                if validation_messages:
                    for msg in validation_messages:
                        st.markdown(msg)
                else:
                    st.info("No advanced validation fields provided.")

            # save result to firestore
            firestore_db.collection("reports").add({
                "user_id": st.session_state.get("user_int_id"),
                "amount": amount,
                "is_international": international,
                "fraud_prediction": final_label,
                "fraud_probability": risk_score,
                "cc_provided": bool(credit_card),
                "phone_provided": bool(phone),
                "upi_provided": bool(upi),
                "email_provided": bool(email),
                "credit_score": credit_score,
                "created_at": datetime.utcnow()
            })

            # save result to MySQL
            conn = get_db_connection()
            if conn:
                cursor = conn.cursor()
                sql = "INSERT INTO reports (customer_id, amount, is_international, fraud_prediction, fraud_probability) VALUES (%s, %s, %s, %s, %s)"
                val = (st.session_state.get("user_int_id"), amount, international, final_label, risk_score)
                cursor.execute(sql, val)
                conn.commit()
                cursor.close()
                conn.close()

            st.success("Prediction: " + final_label)
            st.metric("Risk Score", str(risk_score) + "/100")

# routing
if "page" not in st.session_state:
    st.session_state.page = "home"

check_payment_status()

if "payment_success" in st.session_state and st.session_state.payment_success:
    st.success("Payment successful! You now have unlimited predictions.")
    st.session_state.payment_success = False

if st.session_state.get("user_id"):
    dashboard()
elif "code" in st.query_params:
    google_login_flow()
elif st.session_state.page == "register":
    register()
else:
    home()
