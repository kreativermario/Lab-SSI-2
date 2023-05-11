import json
import socket
import time

from utils import do_encrypt_with_passphrase, \
    decipher_with_private_key, create_key_pair, read_key_pair, \
    create_CSR, read_crt, read_csr, load_csr_and_issue_certificate, \
    create_self_signed_certificate

parameters = {
    "keysize": 2048,
    "password": "password",
    "country_name": "PT",
    "state_or_province_name": "Lisboa",
    "locality_name": "Lisboa",
    "organization_name": "ISCTE-IUL",
    "common_name": "Bob",
}


def init_certificate_authority():
    create_key_pair("ca.key", parameters["keysize"], parameters["password"])
    privkey = read_key_pair("ca.key", parameters["password"])
    create_self_signed_certificate(privkey, "PT",
                                   "Lisboa",
                                   "Lisboa",
                                   "DBM Cyber Consulting",
                                   "DBM")


class Bob:
    def __init__(self, port):
        self.params = None
        self.conn = self.init_socket(port)
        # Criar a chave privada e pública do Bob
        self.init_certificate()
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

    def init_certificate(self):
        create_key_pair("bob.key", parameters["keysize"], parameters["password"])
        self.private_key_bob = read_key_pair("bob.key", parameters["password"])

        create_CSR(self.private_key_bob, parameters["country_name"],
                   parameters["state_or_province_name"],
                   parameters["locality_name"],
                   parameters["organization_name"],
                   parameters["common_name"],
                   "bob.csr")
        ca_cert = read_crt("root_certificate.pem")
        csr = read_csr("bob.csr")
        load_csr_and_issue_certificate(self.private_key_bob, ca_cert,
                                       csr, "bob.crt")
        self.bob_cert = read_crt("bob.crt")

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
        self.conn.sendall(self.bob_cert)
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


init_certificate_authority()
bob = Bob(44444)
