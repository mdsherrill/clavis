from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

message = b'EighteenByteMessag'
print('Message Length: ', len(message))

# Save the key to the "secret.key" file
secret_key = os.urandom(16)
with open("key.txt", "wb") as key_file:
    key_file.write(secret_key)

# Read the shared secret key from a file
with open("key.txt", "rb") as key_file:
    secret_key = key_file.read()

# Create an AES cipher object with CBC mode
cipher = Cipher(algorithms.AES(secret_key), modes.CBC(b'\0'*16))
encryptor_text = cipher.encryptor()

# Input the message from the command line
message = input("Enter the message to encrypt: ").encode()

# Encrypt the message
ciphertext = encryptor_text.update(message) + encryptor_text.finalize()
print("Alice's ciphertext sent to Bob: ", ciphertext.decode('windows-1252'))

# Print the derived ciphertext
print("Derived Ciphertext:", ciphertext.hex())  # Convert to hexadecimal for easy printing

# Write the ciphertext to a file
with open("ctext.txt", "wb") as ctext_file:
    ctext_file.write(ciphertext)

# Read the shared secret key from a file
with open("key.txt", "rb") as key_file:
    secret_key = key_file.read()

# Create an AES cipher object with CBC mode
cipher = Cipher(algorithms.AES(secret_key), modes.CBC(b'\0'*16))
decrypted = cipher.decryptor()

# Read the ciphertext from the file
with open("ctext.txt", "rb") as ctext_file:
    ciphertext = ctext_file.read()

# Decrypt the ciphertext
decrypted_message = decrypted.update(ciphertext) + decrypted.finalize()

# Print the decrypted message
print("Received Ciphertext:", ciphertext.hex())  # Print the received ciphertext in hexadecimal
print("Decrypted message:", decrypted_message.decode())

