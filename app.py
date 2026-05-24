from flask import Flask, request, jsonify, session, render_template, redirect
import sqlite3
import bcrypt
import logging
import os
import base64

# New Security Imports
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
app.secret_key = 'super_secret_key_change_this_later'

# ----------------------------------------------------
# RATE LIMITER SETUP
# ----------------------------------------------------
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Custom error handler for rate limits to prevent raw app crashes
@app.errorhandler(429)
def ratelimit_handler(e):
    return f"<h1>Too Many Requests</h1><p>{e.description}</p><p>Please wait before trying again.</p><a href='/'>Go Back</a>", 429

# ----------------------------------------------------
# SECURITY & KEY DERIVATION LOGIC
# ----------------------------------------------------
if not os.path.exists('logs'):
    os.makedirs('logs')
logging.basicConfig(filename='logs/security.log', level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

# FIX 1: Deterministic per-user key derivation function
def generate_user_key(password, email):
    # Use the user's email as a unique salt (padded to 16 bytes minimum)
    salt = email.encode('utf-8').ljust(16, b'\x00')[:16]
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8'))).decode('utf-8')

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

# ----------------------------------------------------
# FRONTEND ROUTES
# ----------------------------------------------------
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect('/dashboard')
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/')
    is_unlocked = session.get('vault_unlocked', False)
    return render_template('dashboard.html', email=session['email'], vault_unlocked=is_unlocked)

@app.route('/success/<action>')
def success_screen(action):
    return render_template('success.html', action=action)

@app.route('/logout')
def logout():
    logging.info(f"User logged out: {session.get('email')}")
    session.clear() # Securely clears the encryption key from session memory
    return redirect('/')

# ----------------------------------------------------
# BACKEND API ENDPOINTS
# ----------------------------------------------------
@app.route('/register', methods=['POST'])
@limiter.limit("3 per minute") # FIX 2: Protect registration against automated spam
def register():
    email = request.form.get('email')
    password = request.form.get('password')

    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('INSERT INTO users (email, password) VALUES (?, ?)', (email, hashed_password.decode('utf-8')))
        conn.commit()
        logging.info(f"New user registered: {email}")
        return redirect('/success/register')
    except sqlite3.IntegrityError:
        return render_template('login.html', error="Email already registered")
    finally:
        conn.close()

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute") # FIX 2: Prevent brute forcing master passwords
def login():
    email = request.form.get('email')
    password = request.form.get('password')

    conn = get_db_connection()
    cursor = conn.cursor()
    user = cursor.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
    conn.close()

    if user and bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
        session['user_id'] = user['id']
        session['email'] = user['email']
        session['vault_unlocked'] = False  
        
        # Derive and cache the user's specific key in their signed session
        session['encryption_key'] = generate_user_key(password, email)
        
        logging.info(f"Successful login: {email}")
        return redirect('/success/login')
    else:
        logging.warning(f"Failed login attempt for: {email} from {request.remote_addr}")
        return render_template('login.html', error="Invalid email or password")

@app.route('/api/unlock', methods=['POST'])
@limiter.limit("5 per minute") # FIX 2: Prevent brute forcing the in-dashboard prompt
def api_unlock():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.get_json()
    password = data.get('password')
    
    conn = get_db_connection()
    user = conn.cursor().execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    conn.close()

    if user and bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
        session['vault_unlocked'] = True 
        
        # Re-verify and ensure key is active in the session
        session['encryption_key'] = generate_user_key(password, session['email'])
        
        logging.info(f"Vault unlocked for user: {session['email']}")
        return jsonify({"message": "Vault unlocked"}), 200
    else:
        logging.warning(f"Failed vault unlock attempt for: {session['email']}")
        return jsonify({"error": "Incorrect password"}), 401

@app.route('/credentials', methods=['POST', 'GET'])
def credentials_api():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    user_key = session.get('encryption_key')
    if not user_key:
        return jsonify({"error": "Encryption key missing. Please log in again."}), 401

    cipher = Fernet(user_key.encode('utf-8'))
    conn = get_db_connection()
    cursor = conn.cursor()

    if request.method == 'POST':
        data = request.form if request.form else request.get_json()
        site = data.get('site')
        username = data.get('username')
        password = data.get('password')

        encrypted_password = cipher.encrypt(password.encode('utf-8')).decode('utf-8')
        cursor.execute('INSERT INTO credentials (user_id, site, username, password) VALUES (?, ?, ?, ?)',
                       (session['user_id'], site, username, encrypted_password))
        conn.commit()
        conn.close()
        return redirect('/dashboard')

    elif request.method == 'GET':
        rows = cursor.execute('SELECT * FROM credentials WHERE user_id = ?', (session['user_id'],)).fetchall()
        conn.close()
        vault_list = []
        is_unlocked = session.get('vault_unlocked', False)
        
        for row in rows:
            if is_unlocked:
                try:
                    decrypted_password = cipher.decrypt(row['password'].encode('utf-8')).decode('utf-8')
                except Exception:
                    decrypted_password = "[Decryption Error]"
            else:
                decrypted_password = "********"
                
            vault_list.append({"id": row['id'], "site": row['site'], "username": row['username'], "password": decrypted_password})
        return jsonify(vault_list), 200

@app.route('/credentials/<int:cred_id>', methods=['DELETE'])
def delete_credential(cred_id):
    if 'user_id' not in session or not session.get('vault_unlocked'):
        return jsonify({"error": "Vault is locked"}), 401
        
    conn = get_db_connection()
    conn.cursor().execute('DELETE FROM credentials WHERE id = ? AND user_id = ?', (cred_id, session['user_id']))
    conn.commit()
    conn.close()
    return jsonify({"message": "Credential deleted"}), 200

if __name__ == '__main__':
    app.run(debug=True)