# importing Flask and other modules
from flask import Flask, render_template, request, url_for, flash, redirect

# Flask constructor
app = Flask(__name__)

# A decorator used to tell the application
# which URL is associated function

# Creating a route that has both GET and POST request methods


@app.route('/', methods=['GET', 'POST'])
def msg_retriever():
    """Coge el mensaje del formulario y lo guarda"""
    
    if request.method == 'POST':
        msg_a = request.form.get('msgA')
        msg_b = request.form.get('msgB')

        if msg_a:
            print(f"\nMensaje enviado del usuario A al usuario B: {msg_a}\n")
            return f"Mensaje enviado del usuario A al usuario B: {msg_a}"
        print(f"\nMensaje enviado del usuario B al usuario A: {msg_b}\n")
        return f"Mensaje enviado del usuario B al usuario A: {msg_b}"

    # Else, if the request method is GET
    return render_template('index.html')




# Initiating the application
if __name__ == '__main__':
    # Running the application and leaving the debug mode ON
    app.run(debug=True)
