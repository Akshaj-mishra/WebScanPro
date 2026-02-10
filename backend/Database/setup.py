import firebase_admin
from firebase_admin import credentials, firestore
import os
from dotenv import load_dotenv

load_dotenv()

firebase_credentials_path = os.getenv(
    "FIREBASE_CREDENTIALS_PATH",
    "serviceAccountKey.json"
)

if not os.path.exists(firebase_credentials_path):
    raise FileNotFoundError(
        f"Firebase credentials not found at {firebase_credentials_path}"
    )

cred = credentials.Certificate(firebase_credentials_path)
firebase_admin.initialize_app(cred)

db = firestore.client()
