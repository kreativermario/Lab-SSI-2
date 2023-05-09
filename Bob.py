import socket

import pk_encryption
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from utils import generate_certificate

# Dados para o certificado digital
country_name = "PT"
state_or_province_name = "Lisboa"
locality_name = "Lisboa"
organization_name = "ISCTE-IUL"
common_name = "olabob.pt"

# Criar a chave privada e pública do Bob
private_key_bob = pk_encryption.create_key_pair(2048)
public_key_bob = private_key_bob.public_key()
print(pk_encryption.print_key(private_key_bob))

cert = generate_certificate(country_name, state_or_province_name,
                            locality_name, organization_name,
                            common_name, private_key_bob, public_key_bob)
# Serializar o certificado digital do Bob
cert_bytes = cert.public_bytes(serialization.Encoding.PEM)

# Serializar a chave pública do Bob
public_key_bob_bytes = public_key_bob.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)

# Crie um socket para escutar as conexões
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind(("localhost", 12345))
    s.listen()
    conn, addr = s.accept()
    with conn:

        while True:
            message = conn.recv(2048)
            if message == b'GET_CERTIFICATE':
                print("Recebido GET_CERTIFICATE da Alice")
                conn.sendall("SEND_CERTIFICATE".encode())
                conn.sendall(cert_bytes)
                print("Enviado SEND_CERTIFICATE à Alice")



