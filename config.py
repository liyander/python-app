from flask import Flask

class Config:
    DEBUG = True
    TESTING = False
    SECRET_KEY = 'your_secret_key_here'
    DATABASE_URI = 'sqlite:///phishing_detector.db'
    # Add other configuration variables as needed

def init_app(app):
    app.config.from_object(Config)