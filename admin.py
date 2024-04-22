import os

class Secret:
    FLASK_KEY = os.environ.get('FLASK_KEY')
    DB_URI = os.environ.get('DB_URI')

class Admin:
    ADMINS = ['aaryan12jul@gmail.com']

class Premium:
    PAID = []