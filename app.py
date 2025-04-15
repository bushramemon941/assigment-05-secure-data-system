import streamlit as st 
import hashlib
from cryptography.fernet import Fernet
import json
import os 
import time
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac

# Constants
DATA_FILE = "secured_data.txt"
SALT = b"secure_salt_value"
LOCKOUT_DURATION = 60

# Session state initialization
if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0

# Utility functions
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

def generate_key(passkey):
    key = pbkdf2_hmac("sha256", passkey.encode(), SALT, 100000)
    return urlsafe_b64encode(key)

def hash_password(password):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), SALT, 100000).hex()

def encrypt_text(text, key):
    cipher = Fernet(generate_key(key))
    return cipher.encrypt(text.encode()).decode()

def decrypt_text(encrypted_text, key):
    try:    
        cipher = Fernet(generate_key(key))
        return cipher.decrypt(encrypted_text.encode()).decode()
    except:
        return None

# Load data
stored_data = load_data()

# Sidebar Navigation
st.sidebar.title("🔒 SecureVault")
menu = ["Home", "Register", "Login", "Store Data", "Retrieve Data"]
choice = st.sidebar.radio("Navigation", menu)

if choice == "Home":
    st.title("🔐 Secure Data Encryption System")
    st.write("Welcome to SecureVault! A secure place to encrypt, store, and retrieve your sensitive data safely.")

elif choice == "Register":
    st.title("📝 Create New Account")
    with st.form("register_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        confirm_password = st.text_input("Confirm Password", type="password")
        submitted = st.form_submit_button("Register")
        if submitted:
            if not username or not password or not confirm_password:
                st.error("All fields are required")
            elif password != confirm_password:
                st.error("Passwords do not match")
            elif username in stored_data:
                st.error("Username already exists")
            else:
                stored_data[username] = {
                    "password": hash_password(password),
                    "data": []
                }
                save_data(stored_data)
                st.success("Account created successfully! Please login.")
                st.balloons()

elif choice == "Login":
    st.title("🔐 Secure Login")
    if time.time() < st.session_state.lockout_time:
        remaining = int(st.session_state.lockout_time - time.time())
        st.error(f"Too many attempts. Try again in {remaining} seconds.")
        st.stop()

    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Login")
        if submitted:
            if username in stored_data and stored_data[username]["password"] == hash_password(password):
                st.session_state.authenticated_user = username
                st.session_state.failed_attempts = 0
                st.success("Login successful!")
                time.sleep(1)
                st.rerun()  # ✅ THIS IS THE FIXED LINE
            else:
                st.session_state.failed_attempts += 1
                remaining_attempts = 3 - st.session_state.failed_attempts
                if remaining_attempts > 0:
                    st.error(f"Invalid credentials. {remaining_attempts} attempts remaining.")
                else:
                    st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                    st.error("Too many failed attempts. Account locked.")

elif choice == "Store Data":
    if not st.session_state.authenticated_user:
        st.warning("Please login to access this section.")
    else:
        st.title("🔐 Store Encrypted Data")
        with st.form("store_form"):
            data_name = st.text_input("Data Name", placeholder="Optional")
            data_content = st.text_area("Data to Encrypt")
            passkey = st.text_input("Passphrase", type="password")
            submitted = st.form_submit_button("Encrypt & Store")
            if submitted:
                if not data_content or not passkey:
                    st.error("All fields are required.")
                else:
                    encrypted = encrypt_text(data_content, passkey)
                    entry = {
                        "name": data_name if data_name else f"Entry {len(stored_data[st.session_state.authenticated_user]['data']) + 1}",
                        "content": encrypted,
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                    }
                    stored_data[st.session_state.authenticated_user]["data"].append(entry)
                    save_data(stored_data)
                    st.success("Data encrypted and stored!")
                    st.info("⚠️ Remember your passphrase. It cannot be recovered.")

elif choice == "Retrieve Data":
    if not st.session_state.authenticated_user:
        st.warning("Please login to access this section.")
    else:
        st.title("🔓 Retrieve Encrypted Data")
        user_entries = stored_data[st.session_state.authenticated_user]["data"]
        if not user_entries:
            st.info("No data found.")
        else:
            names = [f"{entry['name']} ({entry['timestamp']})" for entry in user_entries]
            selected = st.selectbox("Select Entry", names)
            index = names.index(selected)
            encrypted_data = user_entries[index]["content"]
            with st.form("decrypt_form"):
                passkey = st.text_input("Passphrase", type="password")
                submitted = st.form_submit_button("Decrypt")
                if submitted:
                    decrypted = decrypt_text(encrypted_data, passkey)
                    if decrypted:
                        st.success("Decryption successful!")
                        st.text_area("Decrypted Data", decrypted, height=200)
                    else:
                        st.error("Incorrect passphrase or corrupted data.")
