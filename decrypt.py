# decryption.py
import os
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as symmetric_padding

# Your private key for decryption
PRIVATE_KEY_PEM = b"""
-----BEGIN PRIVATE KEY-----
[Your private key here]
-----END PRIVATE KEY-----
"""

def decrypt_file(file_path):
    """Decrypts a file encrypted with hybrid encryption"""
    if not file_path.endswith('.encrypted'):
        return
        
    # Load the private key
    private_key = serialization.load_pem_private_key(
        PRIVATE_KEY_PEM,
        password=None
    )
    
    # Read the encrypted file
    with open(file_path, "rb") as f:
        # Read the length of encrypted key
        key_length = int.from_bytes(f.read(4), byteorder='big')
        
        # Read and decrypt the AES key
        encrypted_key = f.read(key_length)
        aes_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Read the IV and encrypted data
        iv = f.read(16)
        encrypted_data = f.read()
    
    # Decrypt the file content with AES
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    
    # Remove padding
    unpadder = symmetric_padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    
    # Write the decrypted file
    output_path = file_path[:-10]  # Remove '.encrypted'
    with open(output_path, "wb") as f:
        f.write(data)
    
    # Remove the encrypted file
    os.remove(file_path)
    print(f"Decrypted: {output_path}")

def decrypt_directory(directory):
    """Recursively decrypts all encrypted files in a directory"""
    for root, dirs, files in os.walk(directory, topdown=True):
        for filename in files:
            if not filename.endswith('.encrypted'):
                continue
                
            file_path = os.path.join(root, filename)
            try:
                decrypt_file(file_path)
            except Exception as e:
                print(f"Error decrypting {file_path}: {str(e)}")

if __name__ == "__main__":
    directory = os.getcwd()
    print(f"This will decrypt all encrypted files in: {directory}")
    decrypt_directory(directory)