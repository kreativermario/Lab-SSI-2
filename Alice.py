import os
import socket
import time
import pk_encryption
import json
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from utils import print_public_key, generate_secret_key, get_public_key_from_cert, \
    do_decrypt_with_passphrase
from cryptography.hazmat.primitives.asymmetric import padding



# Gere a chave privada e pública da Alice
private_key_alice = pk_encryption.create_key_pair(2048)
#print(pk_encryption.print_key(private_key_alice))

# Criação do socket para comunicação
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("localhost", 44444))

# 1. Alice faz GET_CERTIFICATE ao Bob
message = "GET_CERTIFICATE"
s.sendall(message.encode())
print("Sent GET_CERTIFICATE to Bob\n\n")
time.sleep(0.5)  # Pausa de 0.1 segundo

# 2. Bob faz SEND_CERTIFICATE à Alice
data = s.recv(5000)
print(f"Got {data.decode()} from Bob\n")

# 3. Bob envia certificado do Bob à Alice
bob_cert = s.recv(5000)  # Assume-se que o certificado é menor que 2048 bytes

# Extração da chave pública do Bob
bob_public_key = get_public_key_from_cert(bob_cert)

print(f"Got {print_public_key(bob_public_key)}\n")

# 4. Alice cria chave secreta SK
SK = generate_secret_key(32)

encrypted_SK = pk_encryption.cipher_with_public_key(SK.encode(), bob_public_key)
# 5. Alice encripta SK com chave publica do Bob
# encrypted_SK = bob_public_key.encrypt(
#     SK.encode(),
#     padding.PKCS1v15()
# )

time.sleep(1)
# 6. Alice faz SECRET_KEY ao Bob
message = "SECRET_KEY"
s.sendall(message.encode())
print("Sent SECRET_KEY to Bob!\n")

time.sleep(2)
# 7. Alice envia PARAMS ao Bob
salt = os.urandom(16)
print(f"Generated salt: {salt}\n")
params = {
    "private_key_protocol": "RSA",
    "certificate": "X509",
    "secret": {
        "method": "RAND",
        "size": 32,
        "encryption": {
            "method": "RSA",
            "padding": "OAEP",
            "hash": "SHA256"
        }
    },
    "encryption": {
        "method": "Fernet",
        "key_derivation": {
            "method": "PBKDF2",
            "hash": "SHA3_256",
            "iterations": 100000,
            "salt": salt.hex()
        }
    }
}

time.sleep(2)
s.sendall(json.dumps(params).encode())
print("Sent PARAMS to Bob!\n")

time.sleep(1)
# 8. Alice envia SK encriptada com a chave publica do Bob ao Bob
s.sendall(encrypted_SK)
print("Sent encrypted SK1 to Bob!\n")
time.sleep(1)

# 11. Bob envia mensagem encriptada com SK
encrypted_message = s.recv(5000)
print(f"Got {encrypted_message} from Bob\n")

time.sleep(1)

# 12. Alice decifra mensagem com SK
print("Decrypted message from Bob:")
message = do_decrypt_with_passphrase(encrypted_message, SK.encode(),
                                     salt.hex().encode())

time.sleep(1)
# 13. Alice cria chave secreta SK2
SK2 = generate_secret_key(32)
print(f"\n\nGenerated SK2: {SK2}\n")

# 14. Alice faz RENEW_SECRET_KEY ao Bob
time.sleep(1)
message = "RENEW_SECRET_KEY"
s.sendall(message.encode())
print(f"Sent {message} to Bob!\n")

time.sleep(1)

# 15. Alice encripta SK2 com chave pública do Bob
encrypted_SK2 = pk_encryption.cipher_with_public_key(SK2.encode(), bob_public_key)
print(f"Encrypted SK2: {encrypted_SK2}\n")

# 16. Alice envia SK2 encriptada com a chave pública do Bob
s.sendall(encrypted_SK2)
print("Sent encrypted SK2 to Bob!\n")

# 19. Bob envia mensagem encriptada com SK2 à Alice
encrypted_message2 = s.recv(5000)

# 20. Alice decifra mensagem com SK2
#message2 = decrypt_SK2(encrypted_message2)  # TODO Função a ser implementada