# Secure Chat Application 🔐

A secure messaging system with end-to-end encryption, certificate authentication, and digital signatures using hybrid cryptography.

## Key Features
- AES-128 (EAX mode) message encryption
- X.509 certificate validation with custom CA
- RSA-2048 signatures for message integrity
- Automatic client/server connection
- Detailed cryptographic operation logging

## Installation

# Clone repository
cd secure-chat

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/MacOS
venv\Scripts\activate.bat  # Windows

# Install dependencies
pip install -r requirements.txt

# Generate certificates
mkdir ca users
python generate_certs.py
