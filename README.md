
# 🐝 Honey Encryption with AES-CBC

This Python project demonstrates a basic version of **Honey Encryption**, where incorrect decryption attempts still return believable-looking fake data, instead of throwing errors.

## 🔐 Features

- AES-256 encryption (CBC mode)
- Scrypt key derivation from password
- Decoy data generation for wrong passwords
- UTF-8 handling and PKCS7 padding

## 📦 Requirements

- Python 3.6 or higher
- `cryptography` library

Install dependencies using pip:

```bash
pip install cryptography
```

## 🚀 Usage

Run the script from your terminal:

```bash
python "honey encryption.py"
```

It will:

1. Encrypt a secret message using a password
2. Ask for input to decrypt it
3. Return the real message **if password is correct**
4. Return a fake message **if password is wrong**

## 💡 Example

```text
Enter the password to open the data: VNRVJIET
Data: This is a secret message that needs to be encrypted!

Enter the password to open the data: wrongpass
Data: People will be life society. The learned two could. Time hope past work.
```

## 🧠 How it Works

- A `salt` is randomly generated for each encryption.
- `Scrypt` derives a 256-bit key from the password and salt.
- AES-CBC encrypts the data with this key.
- If decryption fails, a decoy text of the same length is generated using random common English words.

## 📁 File

- `honey encryption.py` – Main Python script

## ⚠️ Disclaimer

This is a **proof-of-concept** and **should not be used for production or real-world security**.

## 👩‍💻 Author

Sreshta Chelumala  
Cybersecurity Student | VNR VJIET
