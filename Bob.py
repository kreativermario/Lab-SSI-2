import json
import socket
import time

from depreciated import pk_encryption
from cryptography.hazmat.primitives import serialization
from utils import generate_certificate, do_encrypt_with_passphrase, \
    decipher_with_private_key

class Bob:
    def __init__(self, port):
        self.params = None
        self.conn = self.init_socket(port)
        # Criar a chave privada e pública do Bob
        self.private_key_bob = pk_encryption.create_key_pair(2048)
        self.public_key_bob = self.private_key_bob.public_key()
        print(pk_encryption.print_key(self.private_key_bob))
        self.bob_cert = generate_certificate("PT", "Lisboa", "Lisboa",
                                             "ISCTE-IUL", "olabob.pt",
                                             self.private_key_bob,
                                             self.public_key_bob)
        # Serializar o certificado digital do Bob
        self.bob_cert_bytes = self.bob_cert.public_bytes(serialization.Encoding.PEM)
        # Serializar a chave pública do Bob
        self.public_key_bob_bytes = self.public_key_bob.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.receive_get_certificate()
        self.send_certificate()
        self.receive_secret_key_message()
        self.receive_params()
        self.decrypted_sk1 = self.receive_encrypted_and_decrypt_sk()
        time.sleep(1)
        self.send_encrypted_message("Olá, Alice!", self.decrypted_sk1)
        self.receive_renew_secret_key()
        self.decrypted_sk2 = self.receive_encrypted_and_decrypt_sk()
        time.sleep(1)
        self.send_encrypted_message("Adeus, Alice!", self.decrypted_sk2)
        time.sleep(1)

    def init_socket(self, port):
        # Criação do socket para comunicação
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("localhost", port))
        s.listen()
        conn, addr = s.accept()
        return conn

    def receive_get_certificate(self):
        # 2. Bob faz SEND_CERTIFICATE à Alice
        data = self.conn.recv(5000)
        print(f"Got {data.decode()} from Alice\n")
        time.sleep(1)

    def send_certificate(self):
        message = "SEND_CERTIFICATE"
        self.conn.sendall(message.encode())
        print(f"Sent {message} to Alice!\n")

        time.sleep(0.5)  # Pausa de 0.5 segundos
        # 3. Bob envia certificado do Bob à Alice
        self.conn.sendall(self.bob_cert_bytes)
        print("Sent digital certificate to Alice!\n")
        time.sleep(1)

    def receive_secret_key_message(self):
        # 6. Alice envia mensagem controlo SECRET_KEY ao Bob
        data = self.conn.recv(5000)
        print(f"Got {data.decode()} from Alice\n")
        time.sleep(2)

    def receive_params(self):
        # 7. Alice envia PARAMS ao Bob
        params_bytes = self.conn.recv(6000)
        self.params = json.loads(params_bytes.decode())
        print(f"Got PARAMS from Alice: {self.params}\n")
        time.sleep(1)

    def receive_encrypted_and_decrypt_sk(self):
        # 8. Alice envia SK encriptada com a chave publica do Bob ao Bob
        print("Receiving encrypted SK from Alice: ")
        encrypted_sk = self.conn.recv(5000)
        decrypted_sk = decipher_with_private_key(self.private_key_bob, encrypted_sk)
        return decrypted_sk

    def send_encrypted_message(self, message, decrypted_sk):
        # 10. Bob encripta mensagem com SK
        print(f"\nSending encrypted {message} message to Alice")
        # Extrair informações dos params
        salt = self.params['encryption']['key_derivation']['salt']
        # 11. Bob envia mensagem encriptada com SK
        encrypted_message = do_encrypt_with_passphrase(message.encode(), decrypted_sk,
                                                       salt.encode())
        self.conn.sendall(encrypted_message)
        print(f"Sent {encrypted_message} to Alice\n")

    def receive_renew_secret_key(self):
        # 14. Alice faz RENEW_SECRET_KEY ao Bob
        self.receive_get_certificate()


bob = Bob(44444)