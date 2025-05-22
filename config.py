import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'qwertyuiop1234567890'
    SQLALCHEMY_DATABASE_URI = 'postgresql://zooob:1q2w3eRT@localhost/flask_auth'
    SQLALCHEMY_TRACK_MODIFICATIONS = False