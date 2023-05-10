import datetime
import os
import base64
from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization


def generate_certificate(country_name, state_or_province_name,
                         locality_name, organization_name,
                         common_name, private_key, public_key):
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country_name),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state_or_province_name),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization_name),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name)
    ]))
    builder = builder.issuer_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country_name),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state_or_province_name),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization_name),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name)
    ]))
    builder = builder.not_valid_before(datetime.datetime.utcnow())
    builder = builder.not_valid_after(datetime.datetime.utcnow() +
                                      datetime.timedelta(days=3650))
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(public_key)
    builder = builder.add_extension(x509.BasicConstraints(ca=True,
                                                          path_length=None),
                                    critical=True)
    builder = builder.add_extension(x509.KeyUsage(digital_signature=True,
                                                  key_encipherment=True,
                                                  key_cert_sign=True, crl_sign=True,
                                                  content_commitment=False,
                                                  data_encipherment=False,
                                                  key_agreement=False,
                                                  encipher_only=False,
                                                  decipher_only=False),
                                    critical=True)

    cert = builder.sign(
        private_key, hashes.SHA256()
    )
    return cert


def get_public_key_from_cert(cert):
    try:
        # Carrega o certificado digital
        certificate = x509.load_pem_x509_certificate(cert)

        # Obtém a chave pública do certificado digital
        public_key_bob = certificate.public_key()
        print("Successfully extracted public key from cert")
        return public_key_bob
    except Exception as e:
        print(f"Error: {e}")
        return None


def print_public_key(pubkey):
    """
    Recebe uma chave pública RSA e retorna sua representação em PEM.

    Args:
        pubkey: objeto RSAPublicKey, chave pública RSA

    Returns:
        str: representação em PEM da chave pública
    """
    pem_pubkey = pubkey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem_pubkey.decode('utf-8')


def generate_secret_key(length):
    print(f"Generating secret key with length {length}")
    secret_key_bytes = os.urandom(length)
    secret_key_b64 = base64.b64encode(secret_key_bytes).decode('utf-8')
    print(f"Generated secret key {secret_key_b64}")
    return secret_key_b64


def do_encrypt_with_passphrase(message, passphrase, salt):
    print("\nEncrypting with a passphrase (derived to a 256-bit secret key using PBKDF2)")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA3_256(),
        length=32,
        salt=salt,
        iterations=100000
    )
    key = base64.urlsafe_b64encode(kdf.derive(passphrase))
    print("KEY = " + str(key))
    f = Fernet(key)
    ciphertext = f.encrypt(message)
    plaintext = f.decrypt(ciphertext)
    print("Ciphertext = " + str(ciphertext))
    #print("Plaintext = " + str(plaintext.decode('utf-8')))
    return ciphertext


def do_decrypt_with_passphrase(ciphertext, passphrase, salt):
    print("\nDecrypting with a passphrase (derived to a 256-bit secret key using PBKDF2)")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA3_256(),
        length=32,
        salt=salt,
        iterations=100000
    )
    key = base64.urlsafe_b64encode(kdf.derive(passphrase))
    print("KEY = " + str(key))
    f = Fernet(key)
    plaintext = f.decrypt(ciphertext)
    print("Plaintext = " + str(plaintext.decode('utf-8')))
    return plaintext


# Decipher a plaintext with the private key
def decipher_with_private_key(privkey, ciphertext):
    print("\nDeciphering with the private key...")
    plaintext = privkey.decrypt(ciphertext, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    print("Plaintext = " + str(plaintext.decode()))
    return plaintext


