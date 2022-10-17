# Planteamiento

- Tenemos 1 usario que accede con su token que ha recibido por correo al banco
- Una vez comprobado su token con el hash de la DB, accederá a una página para las transacciones
- Ahí el usuario envia un mensaje diciendo la cantidad de dinero que mete en el banco
- El banco recibe el mensaje encriptado simetricamente y  **asumiendo que ambo poseen la clave**, lo desencripta
- Despues, el banco envía un mensaje automatico al usuario confirmando la transacción
- Asumimos que el usuario ya está registrado en la DB y ya tiene su token guardado con el hash correspondiente
- Para la prueba usaremos, entre otros:
  - Usuario: José García
  - Token: **1822312231**
  - Token con hash 256: **e770708a8b682abd84de7851950e00479563c4edb57c2af0e77001b28c49887f**
    Elegimos 256 ya que aunque sea más lento al tratarse de un banco, prima mas la seguridad del dinero que la rapidez de comunicación

Notas:
Para crear el archivo de requisitos, use: *pip freeze > requirements.txt*
Para instalar dichos requierements, use: *pip install -r requirements.txt* SINO NO FUNCIONA

Para crear el entorno virtual (NO NECESARIO):
*python -m venv venv*

Para acceder al entorno virtual, estando dentro de la carpeta backend en el terminal, use:
*venv\Scripts\activate*

Para ejecutar flask: *flask run o python app.py*

Código para hacer push si no se detecta el remoto: git push origin HEAD:master

test

# Links de interés:

* **Curso rápido de Flask**
  * https://www.digitalocean.com/community/tutorials/how-to-make-a-web-application-using-flask-in-python-3
  * https://www.geeksforgeeks.org/retrieving-html-from-data-using-flask/
  * https://stackoverflow.com/questions/12277933/send-data-from-a-textbox-into-flask
  * https://www.educative.io/answers/how-to-retrieve-html-data-from-flask
* **Guía para encriptar-desencriptar el archivo.txt**
  * https://www.geeksforgeeks.org/encrypt-and-decrypt-files-using-python/
* JSON
  * https://linuxhint.com/search_json_python/
* IMPORTANTE: PORQ HEMOS ELEGIDO EL TIPO DE CIFRADO EAX
  * [EAX mode - Wikipedia](https://en.wikipedia.org/wiki/EAX_mode)
  * [EAX mode | Crypto Wiki | Fandom](https://cryptography.fandom.com/wiki/EAX_mode)
  *
