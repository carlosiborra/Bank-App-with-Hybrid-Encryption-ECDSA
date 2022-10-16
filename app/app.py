# importing Flask and other modules
from flask import Flask, render_template, request, url_for, flash, redirect

# Flask constructor
app = Flask(__name__)

# A decorator used to tell the application
# which URL is associated function

# Creating a route that has both GET and POST request methods
@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        name = request.form.get('name')
        username = request.form.get('username')
        print(name, username)
        return f'{name}, your username is {username}'
    return render_template('index.html')


# Initiating the application
if __name__ == '__main__':
    # Running the application and leaving the debug mode ON
    app.run(debug=True)