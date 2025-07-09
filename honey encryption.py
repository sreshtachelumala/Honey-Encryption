import os
import random
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import padding

# Function to generate a random key from a password
def generate_key(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(
        salt=salt,
        length=32,  # AES key length is 32 bytes
        n=2**14,    # Cost factor, higher means more secure but slower
        r=8,
        p=1,
        backend=default_backend()
    )
    return kdf.derive(password.encode())  # Generate the key

# Function to encrypt data using AES
def encrypt_data(data: bytes, key: bytes) -> bytes:
    iv = os.urandom(16)  # Generate a random initialization vector (IV)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Padding the data to be a multiple of the AES block size (16 bytes)
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()

    # Encrypt the padded data
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext  # Return the IV + encrypted data

# Function to decrypt data using AES
def decrypt_data(encrypted_data: bytes, key: bytes) -> bytes:
    iv = encrypted_data[:16]  # Extract the IV from the first 16 bytes
    ciphertext = encrypted_data[16:]  # The rest is the actual ciphertext
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Unpadding the decrypted data to get the original content
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    data = unpadder.update(decrypted_data) + unpadder.finalize()
    return data

# Function to generate decoy data (for wrong passwords)
def generate_decoy_data(length: int) -> bytes:
    words = [
        "the", "is", "on", "and", "with", "a", "it", "to", "for", "an", "as",
        "by", "was", "this", "that", "we", "you", "not", "are", "but", "be",
        "have", "had", "has", "will", "they", "them", "at", "from", "or",
        "there", "all", "any", "one", "two", "three", "many", "some", "because",
        "can", "could", "how", "why", "when", "where", "people", "time", "day",
        "life", "work", "love", "dream", "hope", "learn", "grow", "change",
        "learned", "family", "world", "country", "society", "future", "past"
    ]

    fake_content = ""
    while len(fake_content) < length:
        sentence = " ".join(random.choice(words) for _ in range(random.randint(6, 10)))
        sentence = sentence.capitalize() + ". "
        fake_content += sentence

    return fake_content[:length].encode('utf-8')  # Trim and encode

# Encrypt the data with honey encryption
def honey_encrypt_data(data: str, password: str) -> bytes:
    salt = os.urandom(16)  # Generate a unique salt
    key = generate_key(password, salt)
    encrypted_data = encrypt_data(data.encode(), key)
    return salt + encrypted_data

# Decrypt the data with honey encryption
def honey_decrypt_data(encrypted_data: bytes, password: str) -> str:
    salt = encrypted_data[:16]  # Extract the salt
    encrypted_data = encrypted_data[16:]
    key = generate_key(password, salt)

    try:
        decrypted_data = decrypt_data(encrypted_data, key)
        return decrypted_data.decode('utf-8')  # Return decoded data
    except Exception:
        # If decryption fails, return realistic-looking decoy data
        return generate_decoy_data(len(encrypted_data)).decode('utf-8')

# Main function to run the process
def main():
    data = "This is a secret message that needs to be encrypted!"
    password = 'VNRVJIET'

    encrypted_data = honey_encrypt_data(data, password)

    input_password = input("Enter the password to open the data: ")
    decrypted_data = honey_decrypt_data(encrypted_data, input_password)

    print("Data:", decrypted_data)

# Python entry point
if __name__ == "__main__":
    main()
