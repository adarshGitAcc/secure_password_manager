# Secure Password Manager

A lightweight, secure password manager built with Flask and SQLite. This project focuses on implementing robust local cryptography, protecting user data from physical or digital database theft, and stopping automated brute-force attacks.

## Core Features

* **No Plain-Text Storage:** Master passwords are never saved. Authentication relies entirely on secure, salted hashes generated via `bcrypt`.
* **Dynamic Per-User Encryption:** There is no global, static secret key file to steal. When a user logs in, a unique AES-256 (Fernet) encryption key is derived dynamically from their specific master password and email using **PBKDF2** (SHA256, 100,000 iterations). 
* **In-Memory Sessions:** The derived encryption key lives strictly in server-side session memory and is completely wiped the moment the user logs out.
* **On-Demand Action Unlocking:** When viewing the dashboard, passwords stay hidden behind `********` masks. Clicking **Show**, **Copy**, or **Delete** triggers a security pop-up asking for the master password. Once verified, actions stay unlocked for the rest of that browser session.
* **XSS Protection:** The front-end UI completely avoids dangerous `innerHTML` rendering. Table data is injected as plain text nodes via `textContent`, making embedded malicious scripts entirely non-executable.
* **Rate Limiting:** Built-in protection via `Flask-Limiter` throttles automated scripting. Repeated login or unlock attempts will result in a hard `429 Too Many Requests` timeout.
* **Activity Logs:** All critical actions (successful/failed logins, new registrations, and logouts) are captured locally inside `/logs/security.log`.

---

## Project Structure

```text
password-manager/
├── app.py              # Main Flask server and application logic
├── init_db.py          # Script to initialize the SQLite database
├── database.db         # The local SQLite database file
├── requirements.txt    # Project dependencies
├── README.md           # This documentation file
├── templates/          # Frontend HTML layouts
│   ├── login.html      # Login and signup portal
│   ├── dashboard.html  # Vault interface with the security pop-up modal
│   └── success.html    # Success feedback banner
└── logs/
    └── security.log    # Security tracking and audit logs