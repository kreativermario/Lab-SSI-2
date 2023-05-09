import socket
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from utils import print_public_key, generate_secret_key
from cryptography.hazmat.primitives.asymmetric import padding
import pk_encryption

# Gere a chave privada e pública da Alice
private_key_alice = pk_encryption.create_key_pair(2048)
public_key_alice = private_key_alice.public_key()
#print(pk_encryption.print_key(private_key_alice))

# Serializar a chave pública da Alice para enviar ao Bob
public_key_alice_bytes = public_key_alice.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)

SK1=None

# Crie um socket para se conectar ao Bob
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect(("localhost", 12345))
    # Mensagem que será enviada
    message = "GET_CERTIFICATE"

    # Codifica a mensagem para bytes
    message_bytes = message.encode()

    # Envia a mensagem para o Bob
    s.sendall(message_bytes)
    with s:
        while True:
            message = s.recv(2048)

            if message == b"SEND_CERTIFICATE":
                # Recebe o certificado digital do Bob
                cert = s.recv(4000)

                print("Bob's certificate: ", cert)
                # Carrega o certificado digital
                certificate = x509.load_pem_x509_certificate(cert)

                # Obtém a chave pública do certificado digital
                public_key_bob = certificate.public_key()

                # Serializa a chave pública do Bob para enviar a mensagem criptografada
                public_key_bob_bytes = public_key_bob.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )

                print(print_public_key(public_key_bob))
                SK1 = generate_secret_key(32)
                encrypted_sk1 = public_key_bob.encrypt(
                    SK1.encode(),
                    padding.PKCS1v15()
                )
                print(f"Encrypted SK1: {encrypted_sk1}")

                # Faz alguma outra coisa com a chave pública
                break

            # Se a mensagem recebida não for "SEND_CERTIFICATE", a Alice pode lidar com ela de outra forma aqui
            else:
                # Faz alguma outra coisa
                pass
