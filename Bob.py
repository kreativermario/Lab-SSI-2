import socket
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

# Gere a chave privada e pública do Bob
private_key_bob = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

print(f"Bob private key: {0}", private_key_bob)

public_key_bob = private_key_bob.public_key()

print(f"Bob public key: {0}", public_key_bob)

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
        # Receba a chave pública da Alice
        public_key_alice_bytes = conn.recv(2048)

        # Carregar a chave pública da Alice
        public_key_alice = serialization.load_pem_public_key(
            public_key_alice_bytes
        )

        print(f"Received Alice public key: {0}", public_key_alice)

        # Envie a chave pública do Bob para a Alice
        conn.sendall(public_key_bob_bytes)

        # Receba a mensagem criptografada da Alice
        encrypted_message = conn.recv(2048)

        # Descriptografe a mensagem usando a chave privada do Bob
        decrypted_message = private_key_bob.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        # Exibir a mensagem descriptografada
        print("Mensagem recebida da Alice:", decrypted_message.decode())
