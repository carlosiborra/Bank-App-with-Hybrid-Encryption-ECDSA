""" Flask app docstring """
# importing Flask and other modules
from flask import Flask, render_template, request
from Crypto.PublicKey import RSA
from encriptado import get_key, hash_msg
from encriptado import cifrado_asimetrico, descifrado_asimetrico
from encriptado import cifrado_simetrico, descifrado_simetrico
from encriptado import sign_msg, verify_signature
from jsonConfig import add_money, compare_hash
from ellipticcurve.privateKey import PrivateKey


# Flask constructor
app = Flask(__name__)

# Creating a route that has both GET and POST request methods


@app.route('/', methods=['GET', 'POST'])
def msg_retriever():
    """Coge el mensaje del formulario y lo guarda"""

    global token_usuario

    if request.method == 'POST':
        msg_a = request.form.get('msgA')
        msg_b = request.form.get('msgB')

        if msg_a:
            print(f"\nToken en claro: {msg_a}\n")

            token_hash = hash_msg(msg_a)
            token_usuario = token_hash

            print(f"Hash del token: {token_hash}\n")

            hash_comparison = compare_hash(token_hash)

            print(f"Comparación del hash: {hash_comparison}\n")

            if hash_comparison:
                print("El token introducido es correcto, redirigiendo...\n")
                return render_template('mensaje.html')
            return f"El token introducido {msg_a}, no pertenece a ningún usuario"

        if msg_b:
            try:
                # ? Se almacena la clave publica del banco en private.pem
                llave = RSA.generate(2048)
                module = "23456"
                privada_banco = llave.export_key(passphrase=module)
                with open("private.pem", "wb") as f:
                    f.write(privada_banco)

                # ? Se almacena la clave publica del banco en public.pem
                publica_banco = llave.publickey().export_key()
                with open("public.pem", "wb") as f:
                    f.write(publica_banco)

                # ? Se obtiene la clave simétrica aleatoria de 32 bytes
                key = get_key()
                print(f"LLave simétrica aleatoria: {key}\n")

                # ? Se cifra la clave simétrica usando la clave pública del banco
                # Se obtiene la clave pública del banco
                with open("public.pem", "rb") as f:
                    publica = f.read()
                key_cifrada = cifrado_asimetrico(publica, key)
                print(f"LLave simétrica cifrada: {key_cifrada}\n")

                # ? Se descifra la clave simétrica usando la clave privada del banco
                # Se obtiene la clave privada del banco
                with open("private.pem", "rb") as f:
                    privada = f.read()
                key = descifrado_asimetrico(privada, key_cifrada, module)
                print(f"LLave simétrica descifrada: {key}\n")

                # ? Generamos las clave pública y privada para la firma digital
                # Para ello usamos la curva elíptica secp256k1 (Bitcoin)
                # Creamos la clave privada
                priv_key = PrivateKey()
                # Obtenemos la clave pública a partir de la privada
                pub_key = priv_key.publicKey()
                print(
                    f"Clave privada secp256k1: {priv_key}\nClave pública secp256k1: {pub_key}\n")

                # ? Usamos la clave pública del usuario para firmar el mensaje
                signature = sign_msg(msg_b, priv_key)
                # Transformamos la firma (obj) almacenada en un registro a base64 para imprimirla
                print(f"Firma del mensaje: {signature.toBase64()}\n")

                # ? El mensaje del usuario es encriptado con la llave simetrica usando el modo EAX
                mensaje_encriptado = cifrado_simetrico(key, msg_b)
                print(
                    f"Mensaje cifrado con sus atributos: {mensaje_encriptado}\n")

                # ? El banco desencripta el mensaje con la cantidad de dinero usando el modo EAX
                msg_b = descifrado_simetrico(key, mensaje_encriptado)
                print(f"Mensaje descifrado: {msg_b}\n")

                # ? Se verifica la firma del mensaje usando la clave pública del banco
                verification = verify_signature(msg_b, signature, pub_key)
                # Si la firma es correcta, se continua con el proceso
                # Se compara el hash del msg inicial con el hash del msg descifrado tras la firma
                if verification:
                    print(
                        "La firma del mensaje ha sido verificada satisfactoriamente\n")
                # Si la firma es incorrecta, se notifica al usuario
                else:
                    print("La firma del mensaje ha resultado incorrecta\n")
                    return "La firma del mensaje es incorrecta: el mensaje ha sido modificado"

                # ? Comprobamos que el mensaje sea un número (cantidad de dinero a ingresar)
                if not msg_b.isnumeric():
                    return f"Cantidad errónea: {msg_b}"

                # ? Añadimos la cantidad de dinero a la cuenta del usuario
                add_money(token_usuario, int(msg_b))

                # ? Se termina la transacción, redirigimos al usuario a una página de confirmación
                print(
                    f"\nDinero ingresado en la cuenta del usuario: {msg_b}€\n")
                return f"Operación satisfactoria. Se le ha ingresado en la cuenta {msg_b}€"

            except Exception as error:
                return f"Error al desencriptar el mensaje; Error: {error}"

    # Else, if the request method is GET
    return render_template('index.html')


# Initiating the application
if __name__ == '__main__':
    # Running the application and leaving the debug mode ON
    app.run(debug=True)