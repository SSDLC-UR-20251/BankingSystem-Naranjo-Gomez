from _datetime import datetime
import re

import unicodedata
import unittest


def normalize_input(data):
    if isinstance(data, str):
        # Normalizar el texto a la forma canónica
        data = unicodedata.normalize('NFKD', data)
        # Convertir a minúsculas y eliminar espacios en blanco
        data = data.strip().lower()
    return data


# valido el email
def validate_email(email):
    email = normalize_input(email)
    pattern = r'^[a-zA-Z0-9._%+-]+@urosario\.edu\.co$'
    return re.match(pattern, email) is not None


# valido la edad
def validate_dob(dob):
    birth_date = datetime.strptime(dob, "%Y-%m-%d")
    today = datetime.today()
    age = today.year - birth_date.year

    if (today.month, today.day) < (birth_date.month, birth_date.day):
        age -= 1

    return age >= 18


# valido el usuario
def validate_user(user):
    patron = r'^[a-zA-Z]+\.[a-zA-Z]+$'
    return bool(re.fullmatch(patron, user))


# valido el dni
def validate_dni(dni):
    patron = r'^\d{10}$'
    return bool(re.fullmatch(patron, dni))


# valido la contraseña
def validate_pswd(pswd):
    pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[#*@\$%&\-!+=?])[A-Za-z\d#*@\$%&\-!+=?]{8,35}$'
    return bool(re.fullmatch(pattern, pswd))

def validate_name(name):
    return bool(re.fullmatch(r'^[a-zA-Z]+$', name))

class TestValidationFunctions(unittest.TestCase):
    
    def test_validate_email(self):
        self.assertTrue(validate_email("usuario@urosario.edu.co"))
        self.assertFalse(validate_email("usuario@gmail.com"))
        self.assertFalse(validate_email("usuario@urosario.com"))
        self.assertFalse(validate_email("usuario@urosario.edu"))
        self.assertFalse(validate_email("@urosario.edu.co"))
    
    def test_validate_dob(self):
        self.assertTrue(validate_dob("2000-01-01"))  # Mayor de 16
        self.assertFalse(validate_dob("2010-01-01")) # Menor de 16
    
    def test_validate_user(self):
        self.assertTrue(validate_user("sara.palacios"))
        self.assertFalse(validate_user("sara_palacios"))
        self.assertFalse(validate_user("sarapalacios"))
        self.assertFalse(validate_user("sara.palacios1"))
        self.assertFalse(validate_user("sara.palacios!"))  # No debe contener caracteres especiales
    
    def test_validate_dni(self):
        self.assertTrue(validate_dni("1000000001"))
        self.assertFalse(validate_dni("10000000001"))
        self.assertFalse(validate_dni("abcdefg123"))
    
    def test_validate_name(self):
        self.assertTrue(validate_name("Sara"))
        self.assertTrue(validate_name("Palacios"))
        self.assertFalse(validate_name("Sara123"))
        self.assertFalse(validate_name("Sara_Palacios"))
        self.assertFalse(validate_name("Sara!"))
        self.assertFalse(validate_name("Sara Palacios"))  # No debe contener espacios
    
    def test_validate_password(self):
        self.assertTrue(validate_pswd("Passw0rd!"))  # Cumple con los requisitos
        self.assertFalse(validate_pswd("password"))  # Falta mayúscula, número y especial
        self.assertFalse(validate_pswd("PASSWORD1"))  # Falta minúscula y especial
        self.assertFalse(validate_pswd("Passw0rd"))  # Falta carácter especial
        self.assertFalse(validate_pswd("Pw1!"))  # Demasiado corta
        self.assertFalse(validate_pswd("A" * 36 + "1!"))  # Demasiado larga

if __name__ == "__main__":
    unittest.main()