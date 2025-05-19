import streamlit as st
import requests
from cryptography.hazmat.primitives import serialization, hashes  # Importing cryptographic primitives
from cryptography.hazmat.primitives.asymmetric import padding
from streamlit_autorefresh import st_autorefresh
import time

# ------------------- CONFIG -------------------
BACKEND_URL = "https://cipher-shield.onrender.com"

# ------------------- SESSION STATE -------------------
if 'token' not in st.session_state:
    st.session_state.token = None
if 'refresh' not in st.session_state:
    st.session_state.refresh = None
if 'private_key' not in st.session_state:
    st.session_state.private_key = None
if 'username' not in st.session_state:
    st.session_state.username = None

# ------------------- AUTH FUNCTIONS -------------------
def signup(username, email, password):
    url = f"{BACKEND_URL}/auth/signup/"
    data = {'username': username, 'email': email, 'password': password}
    return requests.post(url, json=data)

def login(username, password):
    url = f"{BACKEND_URL}/auth/login/"
    data = {'username': username, 'password': password}
    response = requests.post(url, json=data)
    if response.status_code == 200:
        tokens = response.json()
        st.session_state.token = tokens['access']
        st.session_state.refresh = tokens['refresh']
        return tokens
    return None

def refresh_token():
    url = f"{BACKEND_URL}/auth/token/refresh/"
    data = {'refresh': st.session_state.refresh}
    response = requests.post(url, json=data)
    if response.status_code == 200:
        new_access = response.json().get('access')
        st.session_state.token = new_access
        return True
    return False

def fetch_private_key():
    url = f"{BACKEND_URL}/auth/private_key/"
    headers = {"Authorization": f"Bearer {st.session_state.token}"}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json().get('private_key')
    return None

# ------------------- CHAT FUNCTIONS -------------------
def send_message(receiver, plain_text):
    url = f"{BACKEND_URL}/chat/send/"
    headers = {"Authorization": f"Bearer {st.session_state.token}"}
    data = {'receiver': receiver, 'plain_text': plain_text}
    response = requests.post(url, headers=headers, json=data)

    if response.status_code == 401 and 'token_not_valid' in response.text:
        # Token expired or invalid — try refreshing
        if refresh_token():
            headers = {"Authorization": f"Bearer {st.session_state.token}"}
            response = requests.post(url, headers=headers, json=data)
    return response

def get_chat_history(other_user):
    url = f"{BACKEND_URL}/chat/history/?with={other_user}"
    headers = {"Authorization": f"Bearer {st.session_state.token}"}
    response = requests.get(url, headers=headers)
    if response.status_code == 401 and 'token_not_valid' in response.text:
        if refresh_token():
            headers = {"Authorization": f"Bearer {st.session_state.token}"}
            response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    return []

def decrypt_message(encrypted_hex, private_key_pem):
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode(),
        password=None,
    )
    encrypted_bytes = bytes.fromhex(encrypted_hex)
    plaintext = private_key.decrypt(
        encrypted_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode()
# ------------------- THREAT DETECTION FUNCTION -------------------
def detect_threats():
    url = f"{BACKEND_URL}/chat/detect_threats/"
    headers = {"Authorization": f"Bearer {st.session_state.token}"}
    response = requests.post(url, headers=headers)
    return response


# ------------------- STREAMLIT UI -------------------
st.title("🔐 Cipher Shield - Secure Chat")

if not st.session_state.token:
    st.subheader("Login / Signup")

    tab1, tab2 = st.tabs(["Login", "Signup"])

    with tab1:
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        if st.button("Login"):
            auth_data = login(username, password)
            if auth_data:
                st.success("Login successful!")
                st.session_state.username = username
                private_key_data = fetch_private_key()
                if private_key_data:
                    st.session_state.private_key = private_key_data
                    st.success("Private key loaded successfully!")
                else:
                    st.error("Failed to fetch private key.")
            else:
                st.error("Login failed.")

    with tab2:
        username = st.text_input("New Username")
        email = st.text_input("Email")
        password = st.text_input("New Password", type="password")
        if st.button("Signup"):
            resp = signup(username, email, password)
            if resp.status_code == 201:
                st.success("Signup successful! Please login.")
            else:
                st.error(f"Signup failed: {resp.text}")

else:
    st.sidebar.title(f"Welcome, {st.session_state.username} 👋")
    st.sidebar.subheader("Chat with Someone:")

    receiver_username = st.sidebar.text_input("Receiver Username")
    message_text = st.sidebar.text_input("Your Message")
    if st.sidebar.button("Send Message"):
        if receiver_username and message_text:
            try:
                send_response = send_message(receiver_username, message_text)
                if send_response.status_code == 201:
                    st.sidebar.success("Message Sent!")
                else:
                    st.sidebar.error(f"Failed to send message: {send_response.text}")
            except Exception as e:
                st.sidebar.error(f"Exception occurred: {str(e)}")

    st.subheader("💬 Live Chat with Another Soldier")

    # Auto refresh every 5 seconds
    count = st_autorefresh(interval=5000, limit=None, key="chat_refresh")
    target_user = st.text_input("Chatting with (username)")

    if target_user:
        chats = get_chat_history(target_user)
        if chats:
            for chat in chats:
                sender = chat['sender']
                encrypted_text = chat['encrypted_text']
                timestamp = chat.get('timestamp', 'Unknown Time')
                try:
                    decrypted_text = decrypt_message(encrypted_text, st.session_state.private_key)
                    if sender == st.session_state.username:
                        st.success(f"🧑‍💻 You ({timestamp}):\n{decrypted_text}")
                    else:
                        st.info(f"👥 {sender} ({timestamp}):\n{decrypted_text}")
                except Exception:
                    st.error("⚠️ Decryption failed.")
    else:
        st.info("No chats yet, start sending messages!")
    # 🔍 Threat Detection Button
    if st.sidebar.button("🔍 Run Threat Detection"):
        if st.session_state.token:
            detection_response = detect_threats()
            if detection_response.status_code == 200:
                result = detection_response.json()
                st.sidebar.success(f"Threat Detection Completed: {result['message']}")
            else:
                st.sidebar.error(f"Error: {detection_response.text}")
        else:
            st.sidebar.error("You must be logged in to detect threats!")


    if st.button("Logout"):
        st.session_state.token = None
        st.session_state.refresh = None
        st.session_state.private_key = None
        st.session_state.username = None
        st.success("Logged out successfully!")
