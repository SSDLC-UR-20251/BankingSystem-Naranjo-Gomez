import json


# Función para leer la "base de datos" (archivo .txt)
def read_db(db):
    try:
        with open(db, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


# Función para escribir en la "base de datos" (archivo .txt)
def write_db(db, data):
    with open(db, 'w') as f:
        json.dump(data, f)
