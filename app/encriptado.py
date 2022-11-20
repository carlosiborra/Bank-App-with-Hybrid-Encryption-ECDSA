""" Encrypt and decrypt messages """
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from json import dumps
from ellipticcurve.ecdsa import Ecdsa
from ellipticcurve.privateKey import PrivateKey



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
    print(f"\nTexto en claro (bytes): {data}\n")

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
# usamos la librería pycoin.ecdsa para poder firmar y verificar la firma

# Función para firmar el mensaje
def sign_msg(priv_key, msg, module="23456"):
    """ Función para firmar el mensaje """
    # ? Hasheamos el mensaje - SHA3-256 (simplifica la longitud posible)
    hashed_message = hash_msg(msg)
    # ? Firmamos el mensaje con la llave privada del banco y el mensaje hasheado - ECDSA
    # Usamos secp256k1 como curva elíptica, la misma que usa Bitcoin
    key = RSA.importKey(priv_key, module)
    signature = Ecdsa.sign(hashed_message, key)
    return signature


# Función para verificar la firma
def verify_signature(pub_key, msg, signature, module="23456"):
    """ Función para verificar la firma """
    # ? Hasheamos el mensaje - SHA3-256 (simplifica la longitud posible)
    hashed_message = hash_msg(msg)
    # ? Verificamos la firma con la llave pública del banco y el mensaje hasheado - ECDSA
    key = RSA.importKey(pub_key, module)
    result = Ecdsa.verify(hashed_message, signature, key)
    return result
