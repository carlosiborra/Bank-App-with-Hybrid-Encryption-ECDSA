""" Encrypt and decrypt messages """
import hashlib
import datetime
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import ec
from jsonConfig import user_name as get_user_name


# ! Obtenemos la llave privada aleatoria de 32 bytes

def get_key() -> bytes:
    """ Función para obtener la llave de 32 bytes aleatoria """
    key = get_random_bytes(32)
    return key


# ! Hash del mensaje

def hash_msg(mensaje="nonValidMsgPredet"):
    """ Función para hashear el mensaje """
    hashed_message = hashlib.sha256(mensaje.encode('utf-8')).hexdigest()
    return hashed_message


# ! Funciones para encriptar y desencriptar la llave simétrica
# Para ello, hemos decido usar el modo EAX de AES para encriptar y desencriptar el mensaje

def cifrado_simetrico(key, message):
    """ Función para encriptar el mensaje """
    # ? Pasar los el texto en claro a bytes
    data = message.encode('utf-8')
    print(f"Texto en claro (bytes): {data}\n")

    # ? Crear el objeto AES con la llave y el modo de operación
    cipher = AES.new(key, AES.MODE_EAX)

    # ? Encriptar el texto en claro
    ciphertext, tag = cipher.encrypt_and_digest(data)
    nonce = cipher.nonce
    stored_text = [nonce, tag, ciphertext]

    return stored_text


def descifrado_simetrico(key, message) -> str:
    """ Función para desencriptar el mensaje """
    # ? Obtenemos los atributos del objeto mensaje cifrado
    nonce = message[0]
    tag = message[1]
    ciphertext = message[2]

    # ? Crear el objeto AES con la llave y el modo de operación
    cipher_decrypt = AES.new(key, AES.MODE_EAX, nonce)

    # ? Desencriptar el mensaje
    data = cipher_decrypt.decrypt_and_verify(ciphertext, tag)

    # ? Lo volvemos a pasar de bytes a string
    data = data.decode('utf-8')
    return data


# ! Cifrado asimétrico con RSA

def cifrado_asimetrico(publica_banco, aes_key) -> bytes:
    """ Función para cifrar la clave simétrica """
    key = RSA.importKey(publica_banco)
    cipher_rsa = PKCS1_OAEP.new(key)
    key_cifrada = cipher_rsa.encrypt(aes_key)
    return key_cifrada


def descifrado_asimetrico(privada_banco, aes_key_cifrada, module="23456") -> bytes:
    """ Función para descifrar la clave simétrica """
    key = RSA.importKey(privada_banco, module)
    cipher_rsa = PKCS1_OAEP.new(key)
    key_descifrada = cipher_rsa.decrypt(aes_key_cifrada)
    return key_descifrada


# ! Firma digital usando ECDSA
# Usamos la librería cryptography para poder firmar y verificar la firma - ECDSA
# Usamos secp256k1 como curva elíptica, la misma que usa Bitcoin

# Función para crear la clave privada
def private_sign_key():
    """ Función para crear la clave privada """
    priv_key = ec.generate_private_key(ec.SECP256K1())

    # Guardamos la clave privada EC en un archivo
    with open("certificate/priv_key.pem", "wb") as f:
        f.write(priv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(
                b"passphrase"),
        ))

    return priv_key


# Función para crear la clave pública
def public_sign_key(priv_key):
    """ Función para crear la clave pública """
    pub_key = priv_key.public_key()

    # Guardamos la clave publica EC en un archivo
    with open("certificate/pub_key.pem", "wb") as f:
        f.write(pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))

    return pub_key


# Función para firmar el mensaje
def sign_msg_cryptography(msg, priv_key):
    """ Función para firmar el mensaje """
    # ? Hasheamos el mensaje - SHA3-256 (simplifica la longitud posible del mensaje)
    hashed_message = hash_msg(msg)
    # ? Firmamos el mensaje con la llave privada del banco y el mensaje hasheado - ECDSA
    # Usamos secp256k1 como curva elíptica, la misma que usa Bitcoin
    signature = priv_key.sign(hashed_message.encode(
        'utf-8'), ec.ECDSA(hashes.SHA256()))
    return signature


# Función para verificar la firma
def verify_sign_cryptography(msg, signature, pub_key):
    """ Función para verificar la firma """
    # ? Hasheamos el mensaje - SHA3-256 (simplifica la longitud posible del mensaje)
    hashed_message = hash_msg(msg)
    # ? Verificamos la firma con la llave pública del banco y el mensaje hasheado - ECDSA
    try:
        pub_key.verify(signature, hashed_message.encode(
            'utf-8'), ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


# ! Certificado digital usando ECDSA
# Función para generar el certificado digital
# Creamos un auto firmado con la librería cryptography para ECDSA
def certificate_sign(priv_key, token):
    """ Función para generar el certificado digital ECDSA """
    print("Generando certificado digital...")

    # Sacamos los datos del usuario de .json actual (nombre, apellidos)
    user_name = get_user_name(token)

    # El usuario es el emisor y el receptor del certificado
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.USER_ID, f"´{user_name}: {token}"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "España"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Madrid"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CriptoBank"),
        x509.NameAttribute(NameOID.COMMON_NAME, "criptobank.transactions.com"),
    ])

    # Imprimimos los datos del certificado (es igual el issuer y el subject al ser auto firmado)
    print("Datos del certificado:", issuer)

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        # ! La clave pública del usuario
        priv_key.public_key()
    ).serial_number(
        # ! Número de serie aleatorio
        x509.random_serial_number()
    ).not_valid_before(
        # ! Nuestro certificado es válido desde el momento de su creación
        datetime.datetime.utcnow()
    ).not_valid_after(
        # ! Nuestro certificado será valido durante 30 minutos
        datetime.datetime.utcnow() + datetime.timedelta(days=0, minutes=30)
    ).add_extension(
        # ! Definido para el localhost (tests
        x509.SubjectAlternativeName([x509.DNSName("localhost")]),
        critical=False,
        # ! Firmamos el certificado con nuestra llave privada
    ).sign(priv_key, hashes.SHA256())
    # Escritura del certificado aleatorio en la carpeta certificate
    with open("certificate/certificate.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print("Certificado generado con éxito\n")


# Función para verificar el certificado digital hecho en ECDSA
def verify_certificate_sign():
    """ Función para verificar el certificado digital """
    with open("certificate/certificate.pem", "rb") as f:
        certificate = x509.load_pem_x509_certificate(
            f.read(),)

    with open("certificate/pub_key.pem", "rb") as f:
        public_key = serialization.load_pem_public_key(
            f.read(),)

    print("Verificando certificado digital con la llave pública del usuario...")
    try:
        public_key.verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            ec.ECDSA(certificate.signature_hash_algorithm),
        )
        print("Certificado digital verificado con éxito\n")
        return True
    except Exception as exception:
        print(f"Certificado inválido: {exception}")
        return False
