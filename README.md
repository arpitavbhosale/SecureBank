# 🏦 Bank Data Privacy Preservation System using Homomorphic Encryption

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.9%2B-3776AB?style=flat-square&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/Flask-2.x-000000?style=flat-square&logo=flask&logoColor=white"/>
  <img src="https://img.shields.io/badge/Firebase-Firestore-FFCA28?style=flat-square&logo=firebase&logoColor=black"/>
  <img src="https://img.shields.io/badge/Encryption-Paillier%20HE-6A0DAD?style=flat-square"/>
</p>

---

## 📌 Abstract

A full-stack banking system that uses **Paillier Homomorphic Encryption** to keep account balances encrypted at all times — even during computation. Deposits, withdrawals, transfers, and portfolio analytics are performed **directly on ciphertexts** without ever decrypting individual balances. The backend is a Flask REST API secured with Firebase JWT authentication, and all encrypted data is stored in Firebase Firestore. A single-page web dashboard provides a complete banking interface.

> Benchmarked at **100% decryption accuracy** (₹0.000000 mean error), ~10ms per encrypt/decrypt, and 0.01ms for homomorphic addition.

---

## 🚀 Project Setup

### 1. Clone & Install

```bash
git clone https://github.com/your-username/banking-he-system.git
cd banking-he-system
pip install flask flask-cors firebase-admin
```

### 2. Firebase Configuration

**Backend** — Download your service account key from Firebase Console → Project Settings → Service Accounts → Generate new private key. Save it as `serviceAccountKey.json` in the project root.

**Frontend** — Open `templates/index.html` and replace the placeholder Firebase config:

```javascript
const firebaseConfig = {
  apiKey:            "YOUR_API_KEY",
  authDomain:        "YOUR_PROJECT.firebaseapp.com",
  projectId:         "YOUR_PROJECT_ID",
  storageBucket:     "YOUR_PROJECT.appspot.com",
  messagingSenderId: "YOUR_SENDER_ID",
  appId:             "YOUR_APP_ID"
};
```

Find these values at: Firebase Console → Project Settings → General → Your Apps.

### 3. Enable Firebase Services

In the Firebase Console, enable:
- **Authentication** → Sign-in method → Email/Password ✓
- **Firestore Database** → Create database (start in test mode) ✓

### 4. Run

```bash
python app.py
```

On first run, a 512-bit Paillier keypair is auto-generated and saved to `data/keys.pkl`. Open `http://localhost:5000` in your browser.

---

## ⚠️ Important

Add the following to your `.gitignore` before pushing:

```gitignore
serviceAccountKey.json   # Firebase private key — never commit
data/keys.pkl            # Paillier keypair — losing this makes all stored ciphertexts unreadable
__pycache__/
*.pyc
venv/
```

---

## 📁 File Structure

```
├── app.py                          # Flask REST API + Firebase auth middleware
├── homomorphic_encryption.py       # Paillier HE implementation from scratch
├── paillier_performance_metrics.py # Benchmark suite
├── templates/index.html            # Web dashboard (Firebase Auth + Fetch API)
├── data/keys.pkl                   # Auto-generated keypair (gitignored)
└── serviceAccountKey.json          # Firebase service account (gitignored)
```
