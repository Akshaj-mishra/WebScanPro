# 🛡️ WebScanPro — Automated Web Application Security Scanner

WebScanPro is a full-stack web application security testing tool designed to automatically scan web apps for common vulnerabilities such as:

* SQL Injection
* Cross-Site Scripting (XSS)
* IDOR (Insecure Direct Object Reference)
* Authentication & session flaws
* Vulnerability reporting

Built using **React (TypeScript)** for frontend and **FastAPI** for backend.

---

## 🚀 Tech Stack

### Frontend

* React + TypeScript
* Vite
* Firebase Auth & Analytics

### Backend

* FastAPI (Python)
* BeautifulSoup / Requests (crawler & scanning)
* Firebase Admin SDK
* Environment-based configuration

---

## 📁 Project Structure

```
WEBSCANPRO/
│
├── backend/
│   ├── Database/
│   │   ├── Routes.py
│   │   ├── schema.py
│   │   └── setup.py
│   │
│   ├── main/
│   │   └── service/
│   │       ├── crawler.py
│   │       ├── payloads.py
│   │       ├── response_gen.py
│   │       └── scanner.py
│   │
│   ├── tests/
│   │   ├── auth_test.py
│   │   ├── idor.py
│   │   ├── sql_injection.py
│   │   └── xss.py
│   │
│   ├── app.py
│   ├── requirements.txt
│   ├── Dockerfile
│   └── serviceAccountKey.json
│
├── frontend/
│
├── .env
├── .env.example
├── docker-compose.yml
└── README.md
```

---

## ⚙️ Backend Setup (FastAPI)

### 1️⃣ Create virtual environment

```bash
cd backend
python -m venv .venv
```

Activate it:

**Windows**

```bash
.venv\Scripts\activate
```

**Mac/Linux**

```bash
source .venv/bin/activate
```

---

### 2️⃣ Install dependencies

```bash
pip install -r requirements.txt
```

---

### 3️⃣ Create `.env` file (Backend)

Example:

```env
GOOGLE_API_KEY='api'                 # get from Gemini AI Studio
Serp_API='api'                      # get from SerpAPI website
FIREBASE_CREDENTIALS_PATH=serviceAccountKey.json
```

---

### 4️⃣ Run backend server

```bash
uvicorn app:app --reload
```

Server will run at:

```
http://127.0.0.1:8000
```

---

## 🎨 Frontend Setup (React + TypeScript)

### 1️⃣ Install packages

```bash
cd frontend
npm install
```

---

### 2️⃣ Create `.env` file (Frontend)

Example:

```env
VITE_apiKey=""
VITE_authDomain=""
VITE_projectId=""
VITE_storageBucket=""
VITE_messagingSenderId=""
VITE_appId=""
VITE_measurementId=""
```

👉 Get these from **Firebase Console → Project Settings → Web App Config**

---

### 3️⃣ Run frontend

```bash
npm run dev
```

Frontend runs at:

```
http://localhost:5173
```

(or whichever Vite shows)

---

## 🔐 How to Collect API Keys

### ✅ Gemini API Key

1. Go to Gemini AI Studio
2. Create API key
3. Paste into:

```env
GOOGLE_API_KEY='your_key_here'
```

---

### ✅ SerpAPI Key

1. Visit serpapi.com
2. Sign up → Dashboard → API Key

```env
Serp_API='your_key_here'
```

---

### ✅ Firebase Credentials

#### Backend:

* Firebase Console → Project Settings → Service Accounts
* Generate private key → download JSON
* Rename to:

```
serviceAccountKey.json
```

#### Frontend:

* Firebase Console → Web App Config → copy VITE values

---

## 📊 Features

✔ Automated crawling of target websites
✔ SQL Injection detection
✔ XSS payload injection
✔ IDOR testing
✔ Authentication testing
✔ Structured vulnerability reports
✔ Modular scanning engine

---

## 🧪 Test Targets Supported

* DVWA
* OWASP Juice Shop
* bWAPP

(Perfect for ethical security testing & learning)

---

## ⚠️ Disclaimer

This tool is for **educational & ethical security testing only**.
Use only on applications you own or have permission to test.
