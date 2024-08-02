# Password Cracker

A versatile password-cracking script that supports various hash types, brute-force attacks, wordlist attacks, and login page brute-forcing with proxy support. This script is designed to be fast and accurate, utilizing asynchronous processing for efficiency.

## Features

- **Hash Cracking**: Supports MD5, SHA-256, and other common hashing algorithms.
- **Brute-Force Attacks**: Allows custom charsets and password lengths.
- **Wordlist Attacks**: Uses wordlists to crack passwords.
- **Login Page Brute-Force**: Performs brute-force attacks on login pages with proxy support.
- **Proxy Support**: Optionally use proxies for login page attacks.

## Installation

1. **Clone the Repository**

   ```bash
   git clone https://github.com/yourusername/password-cracker.git
   cd password-cracker

2. **Create and activate virtualenvironment**
python -m venv venv
source venv/bin/activate  # On Windows, use `venv\Scripts\activate`

3. **Install the required libraries**
pip install -r requirements.txt

## Usage
1. **Brute force attack**
python password_cracker.py hash.txt --charset alphanumeric --length 8 --show-attempts --threads 4

2. **Wordlist attack**
python password_cracker.py hash.txt --wordlist wordlist.txt --show-attempts --threads 4

3. **Login Page Brute Force**
python password_cracker.py hash.txt --url http://example.com/login --success-indicator "Welcome" --wordlist wordlist.txt --proxy http://user:pass@host:port --threads 4
