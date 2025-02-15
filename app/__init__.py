from flask import Flask
import os

app = Flask(__name__, template_folder=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates'))

# Importa las rutas y la API
from app import api, routes