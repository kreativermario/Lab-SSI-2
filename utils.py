import datetime
import os
import base64
from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization


def create_key_pair(filename, keysize, password):
    """
    Cria par de chaves privada e pública
    :param filename: nome do ficheiro a guardar em formato .key
    :param keysize: tamanho da chave
    :param password: password da key
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=keysize)
    with open(filename, "wb") as f:
        f.write(key.private_bytes(encoding=serialization.Encoding.PEM,
                                  format=serialization.PrivateFormat.TraditionalOpenSSL,
                                  encryption_algorithm=serialization.BestAvailableEncryption(password.encode('ascii'))))


def read_key_pair(filename, password):
    """
    Leitura das chaves
    :param filename: nome do ficheiro
    :param password: password da chave
    :return:
    """
    with open(filename, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(), password=password.encode('ascii'))
    return private_key


def create_CSR(key, country_name, state_or_province_name, locality_name,
               organization_name, common_name, filename):
    print("Creating CSR...")
    country_name = country_name
    state_or_province_name = state_or_province_name
    locality_name = locality_name
    organization_name = organization_name
    common_name = common_name
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        # Details to be contained in the certificate
        x509.NameAttribute(NameOID.COUNTRY_NAME, country_name),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state_or_province_name),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization_name),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])).add_extension(
        x509.SubjectAlternativeName([
            # Alternative names for common name
            x509.DNSName(u"mysite.com"),
            x509.DNSName(u"www.mysite.com"),
        ]),
        critical=False,
        # Sign the CSR with our private key
    ).sign(key, hashes.SHA256())
    # write the CSR to disk
    with open(filename, "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))


def create_self_signed_certificate(key, country_name, state_or_province_name,
                                   locality_name, organization_name, common_name):
    print("Creating a self-signed certificate...")

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country_name),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state_or_province_name),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization_name),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        # 10 years in duration
        datetime.datetime.utcnow() + datetime.timedelta(days=3650)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True
    ).add_extension(
        x509.KeyUsage(digital_signature=True, key_encipherment=True, key_cert_sign=True, crl_sign=True,
                      content_commitment=False, data_encipherment=False, key_agreement=False, encipher_only=False,
                      decipher_only=False),
        critical=True
        # Sign the certificate
    ).sign(key, hashes.SHA256())
    # write certificate to disk
    with open("root_certificate.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def load_csr_and_issue_certificate(key, cert, csr, filename):
    x509_ca_cert = x509.load_pem_x509_certificate(cert)

    x509_csr = x509.load_pem_x509_csr(csr)
    if x509_csr.is_signature_valid:
        print("CSR signature is valid!!!")
    else:
        print("CSR signature is invalid!!!")
        return False

    s_cn = x509_csr.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value
    s_st = x509_csr.subject.get_attributes_for_oid(NameOID.STATE_OR_PROVINCE_NAME)[0].value
    s_ln = x509_csr.subject.get_attributes_for_oid(NameOID.LOCALITY_NAME)[0].value
    s_on = x509_csr.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
    s_c = x509_csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

    s_publickey = x509_csr.public_key()

    i_cn = x509_ca_cert.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value
    i_st = x509_ca_cert.subject.get_attributes_for_oid(NameOID.STATE_OR_PROVINCE_NAME)[0].value
    i_ln = x509_ca_cert.subject.get_attributes_for_oid(NameOID.LOCALITY_NAME)[0].value
    i_on = x509_ca_cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
    i_c = x509_ca_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

    print("CSR information")
    print("Country Name: " + s_cn)
    print("State or Province Name: " + s_st)
    print("Locality Name: " + s_ln)
    print("Organization Name: " + s_on)
    print("Common Name: " + s_c)

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, s_cn),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, s_st),
        x509.NameAttribute(NameOID.LOCALITY_NAME, s_ln),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, s_on),
        x509.NameAttribute(NameOID.COMMON_NAME, s_c),
    ])

    issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, i_cn),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, i_st),
        x509.NameAttribute(NameOID.LOCALITY_NAME, i_ln),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, i_on),
        x509.NameAttribute(NameOID.COMMON_NAME, i_c),
    ])

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        s_publickey
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        # 1 year in duration
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
        x509.KeyUsage(digital_signature=True, key_encipherment=True, key_cert_sign=False, crl_sign=False,
                      content_commitment=False, data_encipherment=True, key_agreement=True, encipher_only=False,
                      decipher_only=False),
        critical=True
        # Sign the certificate
    ).sign(key, hashes.SHA256())
    # write certificate to disk
    with open(filename, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    return True


def read_csr(filename):
    with open(filename, "rb") as f:
        csr = f.read()
    return csr


def read_crt(filename):
    with open(filename, "rb") as f:
        cert = f.read()
    return cert


# Print the key pair components
def print_key(privkey):
    pem_privkey = privkey.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8,
                                        encryption_algorithm=serialization.NoEncryption())
    for pemprivkey in pem_privkey.splitlines():
        print(pemprivkey)

    pubkey = privkey.public_key()
    pem_pubkey = pubkey.public_bytes(encoding=serialization.Encoding.PEM,
                                     format=serialization.PublicFormat.SubjectPublicKeyInfo)
    for pempubkey in pem_pubkey.splitlines():
        print(pempubkey)


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
    print("Plaintext = " + str(plaintext.decode('utf-8')))
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
    plaintext = privkey.decrypt(ciphertext,
                                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(),
                                             label=None))
    print("Plaintext = " + str(plaintext.decode()))
    return plaintext


# Ciphers a message with the public key
def cipher_with_public_key(message, pubkey):
    print("\nCiphering with the public key...")

    ciphertext = pubkey.encrypt(message,
                                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(),
                                             label=None))
    print("Ciphertext = " + str(base64.b64encode(ciphertext)))
    return ciphertext
