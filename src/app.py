from flask import Flask
from routes.api import api_bp

app = Flask(__name__)

app.register_blueprint(api_bp)

@app.route('/')
def home():
    return "Hello, Flask is working!"

if __name__ == '__main__':
    app.run(debug=True)