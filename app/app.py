""" Flask app docstring """
# importing Flask and other modules
from flask import Flask, render_template, request
from Crypto.PublicKey import RSA
from encriptado import hash_msg, encriptar_mensaje, desencriptar_mensaje, cifrado_asimetrico, descifrado_asimetrico
from jsonConfig import add_money, compare_hash, get_key
# Flask constructor
app = Flask(__name__)

#Se almacena la clave publica del banco en private.pem
llave= RSA.generate(2048)
secret_code="23456"
privada_banco= llave.export_key(passphrase=secret_code)
with open("private.pem", "wb") as f:
    f.write(privada_banco)

#Se almacena la clave publica del banco en public.pem
publica_banco = llave.publickey().export_key()
with open("public.pem", "wb") as f:
    f.write(publica_banco)


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
                # ? Se obtiene la clave simétrica del usuario de la base de datos
                #key=get_key(token_hash)

                key = b'\x96\x04\xb1k\x0f\x04^\xd3bg\xde\xed4\x128\x11\xa4Zc\xd87?j\xdf\xd6\x91y\x98\x88\xbev\xfa'

                # ? Se cifra la clave simétrica usando la clavce pública del banco
                with open("public.pem", "rb") as f:
                    publica = f.read()
                key_cifrada=cifrado_asimetrico(publica,key)

                # ? Se descifra la clave simétrica usando la clave privada del banco
                with open("private.pem", "rb") as f:
                    privada = f.read()
                key = descifrado_asimetrico(privada,key_cifrada)

                # ? El mensaje del usuario es encriptado con la llave simetrica usando el modo EAX
                mensaje_encriptado = encriptar_mensaje(key, msg_b)
                print(f"Mensaje encriptado con sus atributos: {mensaje_encriptado}\n")

                # ? El banco debe desencriptar el mensaje con la cantidad de dinero usando el modo EAX
                msg_b = desencriptar_mensaje(key, mensaje_encriptado)
                print(f"Mensaje descifrado: {msg_b}\n")

                # ? Comprobamos que el mensaje sea un número (cantidad de dinero a ingresar)
                if not msg_b.isnumeric():
                    return f"Cantidad errónea: {msg_b}"

                # ? Añadimos la cantidad de dinero a la cuenta del usuario
                add_money(token_usuario, int(msg_b))

                # ? Se termina la transacción, redirigimos al usuario a una página de confirmación
                print(f"\nDinero ingresado en la cuenta del usuario: {msg_b}€\n")
                return f"Operación satisfactoria. Se le ha ingresado en la cuenta {msg_b}€"

            except Exception as error:
                return f"Error al desencriptar el mensaje {error}"

    # Else, if the request method is GET
    return render_template('index.html')


# Initiating the application
if __name__ == '__main__':
    # Running the application and leaving the debug mode ON
    app.run(debug=True)