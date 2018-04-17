from flask import Flask, request, render_template
import os



application = Flask(__name__)

@application.route("/script", methods=['POST'])
def script():
    input_string = request.form['data']
    print(input_string)

    os.system('python SendCommandsFunc.py ' + input_string)

    return "backend response"

@application.route('/')
def static_page():
    return render_template('index.html')

if __name__ == "__main__":
    application.run()
