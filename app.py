"""
Flask Backend API for Banking Data Privacy Preservation System
With Firebase Firestore storage and Firebase Authentication.
Each user can only see and manage their own accounts.
"""

from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import os
from datetime import datetime
from homomorphic_encryption import HomomorphicBankingSystem
import pickle
from functools import wraps

# ─── Firebase Admin SDK ───────────────────────────────────────────────────────
import firebase_admin
from firebase_admin import credentials, firestore, auth as fb_auth

# Path to your downloaded service account key JSON file
SERVICE_ACCOUNT_PATH = 'serviceAccountKey.json'

if not firebase_admin._apps:
    cred = credentials.Certificate(SERVICE_ACCOUNT_PATH)
    firebase_admin.initialize_app(cred)

db = firestore.client()
# ─────────────────────────────────────────────────────────────────────────────

app = Flask(__name__)
CORS(app)

# Global encryption system
banking_system = None
DATA_DIR = 'data'
KEYS_FILE = os.path.join(DATA_DIR, 'keys.pkl')


# ─── Auth middleware ──────────────────────────────────────────────────────────
def require_auth(f):
    """Verify Firebase ID token. Sets request.uid and request.user_email."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Missing or invalid Authorization header'}), 401
        id_token = auth_header.split('Bearer ')[1]
        try:
            decoded        = fb_auth.verify_id_token(id_token)
            request.uid    = decoded['uid']
            request.user_email = decoded.get('email', '')
        except Exception as e:
            return jsonify({'error': f'Invalid or expired token: {str(e)}'}), 401
        return f(*args, **kwargs)
    return decorated
# ─────────────────────────────────────────────────────────────────────────────


def initialize_system():
    """Initialize or load the homomorphic encryption keys (stored locally)."""
    global banking_system
    os.makedirs(DATA_DIR, exist_ok=True)
    if os.path.exists(KEYS_FILE):
        with open(KEYS_FILE, 'rb') as f:
            banking_system = pickle.load(f)
        print("Loaded existing encryption keys")
    else:
        banking_system = HomomorphicBankingSystem(bits=512)
        with open(KEYS_FILE, 'wb') as f:
            pickle.dump(banking_system, f)
        print("Generated new encryption keys")


# ─── Firestore helpers — all data scoped to the calling user's UID ───────────
#
#  Firestore structure:
#    users/{uid}/accounts/{account_id}     ← encrypted_balance stored as string
#    users/{uid}/transactions/{txn_id}
#

def _accounts_ref(uid: str):
    return db.collection('users').document(uid).collection('accounts')


def _transactions_ref(uid: str):
    return db.collection('users').document(uid).collection('transactions')


def save_account(uid: str, account_id: str, data: dict):
    """
    Save account to user private collection AND update global registry.
    The registry only stores account_id → owner_uid (no balance, no sensitive data).
    This allows cross-user transfers to find which uid owns any account_id.
    """
    doc = data.copy()
    doc['encrypted_balance'] = str(doc['encrypted_balance'])
    _accounts_ref(uid).document(account_id).set(doc)

    # Global registry: account_id → owner uid (NO sensitive data stored here)
    db.collection('account_registry').document(account_id).set({
        'account_id': account_id,
        'owner_uid':  uid
    })


def load_account(uid: str, account_id: str):
    """Load account for this user, returns None if not found."""
    doc = _accounts_ref(uid).document(account_id).get()
    if not doc.exists:
        return None
    data = doc.to_dict()
    data['encrypted_balance'] = int(data['encrypted_balance'])
    return data


def all_accounts(uid: str):
    """Return all accounts belonging to this user."""
    result = []
    for doc in _accounts_ref(uid).stream():
        data = doc.to_dict()
        data['encrypted_balance'] = int(data['encrypted_balance'])
        result.append(data)
    return result


def save_transaction(uid: str, txn: dict):
    _transactions_ref(uid).document(txn['transaction_id']).set(txn)


def all_transactions(uid: str, limit: int = 50):
    docs = (
        _transactions_ref(uid)
        .order_by('timestamp', direction=firestore.Query.DESCENDING)
        .limit(limit)
        .stream()
    )
    return [doc.to_dict() for doc in docs]


def account_transactions(uid: str, account_id: str):
    docs = (
        _transactions_ref(uid)
        .where('account_id', '==', account_id)
        .order_by('timestamp', direction=firestore.Query.DESCENDING)
        .stream()
    )
    return [doc.to_dict() for doc in docs]


def _new_txn_id():
    return f"TXN{datetime.now().strftime('%Y%m%d%H%M%S%f')}"


def find_account_globally(account_id: str):
    """
    Fast global account lookup using the account_registry collection.
    Step 1: Look up account_registry/{account_id} to get owner_uid
    Step 2: Load the actual account from users/{uid}/accounts/{account_id}
    Returns (uid, account_dict) or (None, None) if not found.
    """
    # Step 1: find which user owns this account_id
    registry_doc = db.collection('account_registry').document(account_id).get()
    if not registry_doc.exists:
        return None, None

    owner_uid = registry_doc.to_dict().get('owner_uid')
    if not owner_uid:
        return None, None

    # Step 2: load the actual account data
    acc_doc = db.collection('users').document(owner_uid).collection('accounts').document(account_id).get()
    if not acc_doc.exists:
        return None, None

    data = acc_doc.to_dict()
    data['encrypted_balance'] = int(data['encrypted_balance'])
    return owner_uid, data

# ─────────────────────────────────────────────────────────────────────────────


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/api/status', methods=['GET'])
@require_auth
def get_status():
    accounts = all_accounts(request.uid)
    txns     = all_transactions(request.uid)
    return jsonify({
        'status':       'online',
        'encryption':   'Paillier Homomorphic Encryption',
        'key_size':     '512 bits',
        'storage':      'Firebase Firestore',
        'accounts':     len(accounts),
        'transactions': len(txns)
    })


@app.route('/api/account/create', methods=['POST'])
@require_auth
def create_account():
    data            = request.json
    account_id      = data.get('account_id', '').strip()
    customer_name   = data.get('customer_name', '').strip()
    initial_balance = float(data.get('initial_balance', 0))

    if not account_id or not customer_name:
        return jsonify({'error': 'Account ID and customer name are required'}), 400
    if load_account(request.uid, account_id):
        return jsonify({'error': 'Account ID already exists'}), 400

    enc_balance = banking_system.encrypt_balance(initial_balance)

    save_account(request.uid, account_id, {
        'account_id':        account_id,
        'customer_name':     customer_name,
        'encrypted_balance': enc_balance,
        'created_at':        datetime.now().isoformat(),
        'account_type':      data.get('account_type', 'Savings'),
        'owner_uid':         request.uid
    })

    save_transaction(request.uid, {
        'transaction_id': _new_txn_id(),
        'account_id':     account_id,
        'type':           'Account Creation',
        'amount':         initial_balance,
        'timestamp':      datetime.now().isoformat(),
        'description':    'Initial deposit'
    })

    return jsonify({'success': True, 'account_id': account_id,
                    'message': 'Account created successfully'})


@app.route('/api/account/<account_id>', methods=['GET'])
@require_auth
def get_account(account_id):
    account = load_account(request.uid, account_id)
    if not account:
        return jsonify({'error': 'Account not found'}), 404
    account['balance'] = round(banking_system.decrypt_balance(account.pop('encrypted_balance')), 2)
    return jsonify(account)


@app.route('/api/account/<account_id>/transactions', methods=['GET'])
@require_auth
def get_account_transactions(account_id):
    if not load_account(request.uid, account_id):
        return jsonify({'error': 'Account not found'}), 404
    return jsonify(account_transactions(request.uid, account_id))


@app.route('/api/transaction/deposit', methods=['POST'])
@require_auth
def deposit():
    data       = request.json
    account_id = data.get('account_id')
    amount     = float(data.get('amount'))

    account = load_account(request.uid, account_id)
    if not account:
        return jsonify({'error': 'Account not found'}), 404
    if amount <= 0:
        return jsonify({'error': 'Amount must be positive'}), 400

    new_enc = banking_system.process_transaction(
        account['encrypted_balance'], amount, is_credit=True)
    account['encrypted_balance'] = new_enc
    save_account(request.uid, account_id, account)

    txn_id = _new_txn_id()
    save_transaction(request.uid, {
        'transaction_id': txn_id,
        'account_id':     account_id,
        'type':           'Deposit',
        'amount':         amount,
        'timestamp':      datetime.now().isoformat(),
        'description':    data.get('description', 'Cash deposit')
    })

    return jsonify({'success': True, 'transaction_id': txn_id,
                    'new_balance': round(banking_system.decrypt_balance(new_enc), 2),
                    'message': 'Deposit successful'})


@app.route('/api/transaction/withdraw', methods=['POST'])
@require_auth
def withdraw():
    data       = request.json
    account_id = data.get('account_id')
    amount     = float(data.get('amount'))

    account = load_account(request.uid, account_id)
    if not account:
        return jsonify({'error': 'Account not found'}), 404
    if amount <= 0:
        return jsonify({'error': 'Amount must be positive'}), 400

    current_balance = banking_system.decrypt_balance(account['encrypted_balance'])
    if current_balance < amount:
        return jsonify({'error': 'Insufficient balance'}), 400

    new_enc = banking_system.process_transaction(
        account['encrypted_balance'], amount, is_credit=False)
    account['encrypted_balance'] = new_enc
    save_account(request.uid, account_id, account)

    txn_id = _new_txn_id()
    save_transaction(request.uid, {
        'transaction_id': txn_id,
        'account_id':     account_id,
        'type':           'Withdrawal',
        'amount':         -amount,
        'timestamp':      datetime.now().isoformat(),
        'description':    data.get('description', 'Cash withdrawal')
    })

    return jsonify({'success': True, 'transaction_id': txn_id,
                    'new_balance': round(banking_system.decrypt_balance(new_enc), 2),
                    'message': 'Withdrawal successful'})


@app.route('/api/transaction/transfer', methods=['POST'])
@require_auth
def transfer():
    data    = request.json
    from_id = data.get('from_account')
    to_id   = data.get('to_account')
    amount  = float(data.get('amount'))

    if amount <= 0:
        return jsonify({'error': 'Amount must be positive'}), 400
    if from_id == to_id:
        return jsonify({'error': 'Cannot transfer to the same account'}), 400

    # FROM account must belong to the logged-in user (security check)
    from_acc = load_account(request.uid, from_id)
    if not from_acc:
        return jsonify({'error': f'Source account {from_id} not found in your accounts'}), 404

    # TO account can belong to ANY user in the bank
    to_uid, to_acc = find_account_globally(to_id)
    if not to_acc:
        return jsonify({'error': f'Destination account {to_id} not found in the bank'}), 404

    # Check sufficient balance
    current_balance = banking_system.decrypt_balance(from_acc['encrypted_balance'])
    if current_balance < amount:
        return jsonify({'error': 'Insufficient balance'}), 400

    # Perform homomorphic operations
    from_acc['encrypted_balance'] = banking_system.process_transaction(
        from_acc['encrypted_balance'], amount, is_credit=False)
    to_acc['encrypted_balance'] = banking_system.process_transaction(
        to_acc['encrypted_balance'], amount, is_credit=True)

    # Save both accounts (possibly under different UIDs)
    save_account(request.uid, from_id, from_acc)
    save_account(to_uid,      to_id,   to_acc)

    txn_id    = _new_txn_id()
    timestamp = datetime.now().isoformat()

    # Log transaction for sender
    save_transaction(request.uid, {
        'transaction_id': txn_id + '_OUT',
        'account_id':     from_id,
        'type':           'Transfer Out',
        'amount':         -amount,
        'timestamp':      timestamp,
        'description':    f'Transfer to {to_id}'
    })

    # Log transaction for receiver (under their own UID)
    save_transaction(to_uid, {
        'transaction_id': txn_id + '_IN',
        'account_id':     to_id,
        'type':           'Transfer In',
        'amount':         amount,
        'timestamp':      timestamp,
        'description':    f'Transfer from {from_id}'
    })

    return jsonify({'success': True, 'transaction_id': txn_id,
                    'message': f'Transfer of ₹{amount} to {to_id} successful!'})


@app.route('/api/analytics/total-balance', methods=['GET'])
@require_auth
def total_balance():
    accounts = all_accounts(request.uid)
    if not accounts:
        return jsonify({'total_balance': 0, 'num_accounts': 0,
                        'message': 'No accounts found'})

    total_enc = accounts[0]['encrypted_balance']
    for acc in accounts[1:]:
        total_enc = banking_system.add_balances(total_enc, acc['encrypted_balance'])

    return jsonify({
        'total_balance': round(banking_system.decrypt_balance(total_enc), 2),
        'num_accounts':  len(accounts),
        'message':       'Calculated on encrypted data without exposing individual balances'
    })


@app.route('/api/accounts', methods=['GET'])
@require_auth
def list_accounts():
    result = []
    for acc in all_accounts(request.uid):
        info = {k: v for k, v in acc.items() if k != 'encrypted_balance'}
        info['balance'] = round(banking_system.decrypt_balance(acc['encrypted_balance']), 2)
        result.append(info)
    return jsonify(result)


@app.route('/api/transactions', methods=['GET'])
@require_auth
def list_transactions():
    return jsonify(all_transactions(request.uid, limit=50))


@app.route('/api/demo/populate', methods=['POST'])
@require_auth
def populate_demo_data():
    demo_accounts = [
        {'account_id': 'ACC001', 'customer_name': 'Rajesh Kumar',  'initial_balance': 25000.00, 'account_type': 'Savings'},
        {'account_id': 'ACC002', 'customer_name': 'Priya Sharma',  'initial_balance': 50000.00, 'account_type': 'Current'},
        {'account_id': 'ACC003', 'customer_name': 'Amit Patel',    'initial_balance': 15000.00, 'account_type': 'Savings'},
        {'account_id': 'ACC004', 'customer_name': 'Sneha Reddy',   'initial_balance': 75000.00, 'account_type': 'Salary'},
        {'account_id': 'ACC005', 'customer_name': 'Vikram Singh',  'initial_balance': 30000.00, 'account_type': 'Savings'},
    ]
    created = 0
    for a in demo_accounts:
        if load_account(request.uid, a['account_id']):
            continue
        save_account(request.uid, a['account_id'], {
            'account_id':        a['account_id'],
            'customer_name':     a['customer_name'],
            'encrypted_balance': banking_system.encrypt_balance(a['initial_balance']),
            'created_at':        datetime.now().isoformat(),
            'account_type':      a['account_type'],
            'owner_uid':         request.uid
        })
        created += 1

    return jsonify({'success': True, 'accounts_created': created,
                    'message': 'Demo data populated successfully'})


if __name__ == '__main__':
    initialize_system()
    print("\n" + "=" * 60)
    print("Banking Data Privacy Preservation System")
    print("Paillier Homomorphic Encryption + Firebase Firestore")
    print("=" * 60 + "\n")
    app.run(debug=True, port=5000)
