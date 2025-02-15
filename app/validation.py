from _datetime import datetime
import re

import unicodedata


def normalize_input(data):
    return data


# valido el email
def validate_email(email):
    dominio = "@urosario.edu.co"
    if dominio in email:
        email = normalize_input(email)
        return True
    return False


# valido la edad
def validate_dob(dob):
    fechanacimiento = datetime.strptime(dob, "%Y-%m-%d")
    fechahoy = datetime.today()
    edad = fechahoy.year - fechanacimiento.year - ((fechahoy.month, fechahoy.day) < (fechanacimiento.month, fechanacimiento.day))
    if edad >= 16:
        return True

    return False


# valido el usuario
def validate_user(user):
    if user.count(".") == 1:
        new_user = user.replace(".", "")
        if new_user.isalpha():
            return True
    return False


# valido el dni
def validate_dni(dni):
    return bool(re.fullmatch(r"1\d{9}", dni))

# valido la contraseña
def validate_pswd(pswd):
    caracteres = "!@#$%^&*()-_=+[]{}|;:'\",.<>?/`~"
    for i in pswd:
        if i.islower():
            for j in pswd:
                if j.isupper():
                    for k in pswd:
                        if k in caracteres:
                            return True
    return False

def validate_name(name):
    return True
