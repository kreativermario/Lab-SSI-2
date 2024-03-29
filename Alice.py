import json
import os
import socket
import time

from utils import print_public_key, generate_secret_key, \
    get_public_key_from_cert, \
    do_decrypt_with_passphrase, cipher_with_public_key, create_key_pair, \
    read_key_pair, create_CSR, read_crt, read_csr, \
    load_csr_and_issue_certificate

parameters = {
    "keysize": 2048,
    "password": "password",
    "country_name": "PT",
    "state_or_province_name": "Lisboa",
    "locality_name": "Lisboa",
    "organization_name": "ISCTE-IUL",
    "common_name": "Alice",
}


def init_socket(port):
    # Criação do socket para comunicação
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("localhost", port))
    return s


class Alice:

    def __init__(self, port):
        self.bob_public_key = None
        self.conn = init_socket(port)
        self.send_get_certificate()
        self.receive_certificate()
        # 4. Alice cria chave secreta SK
        self.sk1 = generate_secret_key(32)
        self.encrypted_sk1 = self.create_encrypted_sk(self.sk1)
        time.sleep(1)
        self.send_secret_key_message()
        self.salt = os.urandom(16)
        self.send_params()
        self.send_encrypted_sk(self.encrypted_sk1)
        self.decrypt_message_with_sk(self.sk1)
        self.sk2 = generate_secret_key(32)
        self.encrypted_sk2 = self.create_encrypted_sk(self.sk2)
        self.send_renew_secret_key()
        self.send_encrypted_sk(self.encrypted_sk2)
        self.decrypt_message_with_sk(self.sk2)

    def init_certificate(self):
        create_key_pair("alice.key", parameters["keysize"], parameters["password"])
        private_key_alice = read_key_pair("alice.key", parameters["password"])

        create_CSR(private_key_alice, parameters["country_name"],
                   parameters["state_or_province_name"],
                   parameters["locality_name"],
                   parameters["organization_name"],
                   parameters["common_name"],
                   "alice.csr")
        ca_cert = read_crt("root_certificate.pem")
        csr = read_csr("alice.csr")
        load_csr_and_issue_certificate(private_key_alice, ca_cert,
                                       csr, "alice.crt")

    def send_get_certificate(self):
        # 1. Alice faz GET_CERTIFICATE ao Bob
        message = "GET_CERTIFICATE"
        self.conn.sendall(message.encode())
        print("Sent GET_CERTIFICATE to Bob\n\n")
        time.sleep(0.5)  # Pausa de 0.1 segundo

    def receive_certificate(self):
        # 2. Bob faz SEND_CERTIFICATE à Alice
        data = self.conn.recv(5000)
        print(f"Got {data.decode()} from Bob\n")

        # 3. Bob envia certificado do Bob à Alice
        bob_cert = self.conn.recv(5000)  # Assume-se que o certificado é menor que 2048 bytes

        # Extração da chave pública do Bob
        self.bob_public_key = get_public_key_from_cert(bob_cert)

        print(f"Got {print_public_key(self.bob_public_key)}\n")
        time.sleep(1)

    def send_secret_key_message(self):
        # 6. Alice faz SECRET_KEY ao Bob
        message = "SECRET_KEY"
        self.conn.sendall(message.encode())
        print("Sent SECRET_KEY to Bob!\n")

        time.sleep(2)

    def create_encrypted_sk(self, sk):
        # 5. Alice encripta SK com chave pública do Bob
        encrypted_sk = cipher_with_public_key(
            sk.encode(), self.bob_public_key)
        return encrypted_sk

    def send_params(self):
        # 7. Alice envia PARAMS ao Bob
        print(f"Generated salt: {self.salt}\n")
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
                    "salt": self.salt.hex()
                }
            }
        }

        time.sleep(2)
        self.conn.sendall(json.dumps(params).encode())
        print("Sent PARAMS to Bob!\n")
        time.sleep(1)

    def send_encrypted_sk(self, encrypted_sk):
        # 8. Alice envia SK encriptada com a chave publica do Bob
        # 15. Alice encripta SK2 com chave pública do Bob
        self.conn.sendall(encrypted_sk)
        print(f"Sent encrypted SK {encrypted_sk} to Bob!\n")
        time.sleep(1)

    def decrypt_message_with_sk(self, sk):
        # 11. Bob envia mensagem encriptada com SK
        encrypted_message = self.conn.recv(5000)
        print(f"Got {encrypted_message} from Bob\n")

        time.sleep(1)

        # 12. Alice decifra mensagem com SK
        print("Decrypted message from Bob:")
        message = do_decrypt_with_passphrase(encrypted_message, sk.encode(),
                                             self.salt.hex().encode())
        print(f"Decrypted message from Bob: {message}")

        time.sleep(1)

    def send_renew_secret_key(self):
        # 14. Alice faz RENEW_SECRET_KEY ao Bob

        message = "RENEW_SECRET_KEY"
        self.conn.sendall(message.encode())
        print(f"Sent {message} to Bob!\n")

        time.sleep(1)


alice = Alice(44444)
