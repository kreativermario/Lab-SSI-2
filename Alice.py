import socket
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

# Gere a chave privada e pública da Alice
private_key_alice = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
print(f"Alice private key {0}", private_key_alice)

public_key_alice = private_key_alice.public_key()

print(f"Alice public key {0}", private_key_alice)

# Serializar a chave pública da Alice para enviar ao Bob
public_key_alice_bytes = public_key_alice.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)

# Crie um socket para se conectar ao Bob
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect(("localhost", 12345))

    # Envie a chave pública da Alice para o Bob
    s.sendall(public_key_alice_bytes)

    # Receba a chave pública do Bob
    public_key_bob_bytes = s.recv(2048)

    # Carregar a chave pública do Bob
    public_key_bob = serialization.load_pem_public_key(
        public_key_bob_bytes
    )

    # Criptografe a mensagem usando a chave pública do Bob
    message = "Olá, Bob!"
    encrypted_message = public_key_bob.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    # Envie a mensagem criptografada para o Bob
    s.sendall(encrypted_message)
