""" Encrypt and decrypt messages """
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# ! Hemos decido usar el modo EAX de AES para encriptar y desencriptar el mensaje


def encriptar_mensaje(key, message):
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


def desencriptar_mensaje(key, message):
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


def hash_msg(mensaje="adasdasd"):
    """ Función para hashear el mensaje """
    hashed_message = hashlib.sha256(mensaje.encode('utf-8')).hexdigest()
    return hashed_message


# ? Para crear una llave aleatoria de 32 bytes, más segura que una llave de 16 bytes
# llave = get_random_bytes(32)

# ? Para añadir un usuario a la base de datos con su token encriptado:
# print(hash_msg("1822311231"))
