import json
import socket
import time

import pk_encryption
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from utils import generate_certificate, do_encrypt_with_passphrase, \
    decipher_with_private_key

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

bob_cert = generate_certificate(country_name, state_or_province_name,
                                locality_name, organization_name,
                                common_name, private_key_bob, public_key_bob)
# Serializar o certificado digital do Bob
bob_cert_bytes = bob_cert.public_bytes(serialization.Encoding.PEM)

# Serializar a chave pública do Bob
public_key_bob_bytes = public_key_bob.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("localhost", 44444))
s.listen()

conn, addr = s.accept()

with conn:
    # 2. Bob faz SEND_CERTIFICATE à Alice
    data = conn.recv(5000)
    print(f"Got {data.decode()} from Alice\n")
    time.sleep(1)

    message = "SEND_CERTIFICATE"
    conn.sendall(message.encode())
    print(f"Sent {message} to Alice!\n")


    time.sleep(0.5)  # Pausa de 0.5 segundos
    # 3. Bob envia certificado do Bob à Alice
    conn.sendall(bob_cert_bytes)
    print("Sent digital certificate to Alice!\n")
    time.sleep(1)
    # 6. Alice envia mensagem controlo SECRET_KEY ao Bob
    data = conn.recv(5000)
    print(f"Got {data.decode()} from Alice\n")

    time.sleep(2)
    # 7. Alice envia PARAMS ao Bob
    params_bytes = conn.recv(6000)
    params = json.loads(params_bytes.decode())
    print(f"Got PARAMS from Alice: {params}\n")
    time.sleep(1)
    # 8. Alice envia SK encriptada com a chave publica do Bob ao Bob
    print("Receiving encrypted SK from Alice: ")
    encrypted_SK = conn.recv(5000)
    decrypted_sk = decipher_with_private_key(private_key_bob, encrypted_SK)

    time.sleep(1)

    # 10. Bob encripta mensagem com SK
    message = "Olá, Alice!"
    print(f"\nSending encrypted {message} message to Alice")
    # Extrair informações dos params
    salt = params['encryption']['key_derivation']['salt']
    # 11. Bob envia mensagem encriptada com SK
    encrypted_message = do_encrypt_with_passphrase(message.encode(), decrypted_sk,
                                                   salt.encode())
    conn.sendall(encrypted_message)
    print(f"Sent {encrypted_message} to Alice\n")

    time.sleep(1)
    # 14. Alice faz RENEW_SECRET_KEY ao Bob
    data = conn.recv(5000)
    print(f"Got {data.decode()} from Alice\n")

    time.sleep(1)
    # 16. Alice envia SK2 encriptada com a chave pública do Bob
    encrypted_SK2 = conn.recv(5000)

    # 17. Bob decifra SK2 com chave privada do Bob
    decrypted_sk2 = decipher_with_private_key(private_key_bob, encrypted_SK2)

    # 18. Bob encripta a mensagem com SK2
    message2 = "How are you, Alice?"
    # encrypted_message2 = encrypt_SK2(message2)  # TODO Função a ser implementada

    # 19. Bob envia mensagem encriptada com SK2 à Alice
    # conn.sendall(encrypted_message2)
