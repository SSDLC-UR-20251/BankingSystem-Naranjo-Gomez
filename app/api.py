from _datetime import datetime
import time
from app.validation import *
from app.reading import *
from flask import request, jsonify, redirect, url_for, render_template, session, make_response
from app import app
from app.encryption import *

login_attempts = {}
MAX_ATTEMPTS = 3
BLOCK_TIME = 300  # 5 minutos en segundos
app.secret_key = get_random_bytes(16)

@app.route('/api/users', methods=['POST'])
def create_record():
    data = request.form
    email = data.get('email')
    username = data.get('username')
    nombre = data.get('nombre')
    apellido = data.get('Apellidos')
    password = data.get('password')
    dni = data.get('dni')
    dob = data.get('dob')
    errores = []
    if not validate_email(email):
        errores.append("Email inválido")
    if not validate_pswd(password):
        errores.append("Contraseña inválida")
    if not validate_dob(dob):
        errores.append("Fecha de nacimiento inválida")
    if not validate_dni(dni):
        errores.append("DNI inválido")
    if not validate_user(username):
        errores.append("Usuario inválido")
    if not validate_name(nombre):
        errores.append("Nombre inválido")
    if not validate_name(apellido):
        errores.append("Apellido inválido")

    if errores:
        return render_template('form.html', error=errores)

    email = normalize_input(email)
    hashed_pwd, salt = hash_with_salt(normalize_input(password))
    dni_cifrado, dni_nonce = encrypt_aes(normalize_input(dni), app.secret_key)

    db = read_db("db.txt")
    db[email] = {
        'nombre': normalize_input(nombre),
        'apellido': normalize_input(apellido),
        'username': normalize_input(username),
        'password': hashed_pwd,
        "password_salt": salt,
        "dni": dni_cifrado,
        "dni_nonce": dni_nonce,
        'dob': normalize_input(dob),
        "role": "user"
    }

    write_db("db.txt", db)
    return redirect("/login")


# Endpoint para el login
@app.route('/api/login', methods=['POST'])
def api_login():
    email = normalize_input(request.form['email'])
    password = normalize_input(request.form['password'])

    db = read_db("db.txt")
    if email not in db:
        error = "Credenciales inválidas"
        return render_template('login.html', error=error)

    # Verificar si el usuario está bloqueado
    if email in login_attempts and login_attempts[email]['blocked_until'] > time.time():
        block_time_remaining = int((login_attempts[email]['blocked_until'] - time.time()) / 60)
        error = f"Cuenta bloqueada. Intenta nuevamente en {block_time_remaining} minutos."
        return render_template('login.html', error=error)

    password_db = db.get(email)["password"]
    salt_db = db.get(email)["password_salt"]

    # Validar si el correo existe en la base de datos
    if compare_salt(password, password_db, salt_db):
        # Resetear intentos fallidos
        login_attempts[email] = {'attempts': 0, 'blocked_until': 0}

        session['email'] = email
        session['role'] = db[email]['role']

        return redirect(url_for('customer_menu'))
    else:
        # Aumentar el contador de intentos fallidos
        if email not in login_attempts:
            login_attempts[email] = {'attempts': 0, 'blocked_until': 0}

        login_attempts[email]['attempts'] += 1

        # Bloquear la cuenta si se exceden los intentos
        if login_attempts[email]['attempts'] >= MAX_ATTEMPTS:
            login_attempts[email]['blocked_until'] = time.time() + BLOCK_TIME
            error = f"Se han excedido los intentos permitidos. Cuenta bloqueada por {BLOCK_TIME // 60} minutos."
        else:
            remaining_attempts = MAX_ATTEMPTS - login_attempts[email]['attempts']
            error = f"Credenciales incorrectas. Tienes {remaining_attempts} intentos restantes."

        return render_template('login.html', error=error)



# Página principal del menú del cliente
@app.route('/customer_menu')
def customer_menu():
    if 'email' not in session:
        # Redirigir a la página de inicio de sesión si el usuario no está autenticado
        error_msg = "Por favor, inicia sesión para acceder a esta página."
        return render_template('login.html', error=error_msg)

    email = session.get('email')
    db = read_db("db.txt")
    transactions = read_db("transaction.txt")
    current_balance = sum(float(t['balance']) for t in transactions.get(email, []))
    last_transactions = transactions.get(email, [])[-5:]
    message = request.args.get('message', '')
    error = request.args.get('error', 'false').lower() == 'true'
    darkmode = request.cookies.get('darkmode', 'light')
    return render_template('customer_menu.html',
                           message=message,
                           nombre=db.get(email)['nombre'],
                           balance=current_balance,
                           last_transactions=last_transactions,
                           error=error,
                           darkmode=darkmode)


# Endpoint para leer un registro
@app.route('/records', methods=['GET'])
def read_record():
    db = read_db("db.txt")
    user_email = session.get('email')
    user = db.get(user_email, None)
    message = request.args.get('message', '')
    darkmode = request.cookies.get('darkmode', 'light')

    if session.get('role') == 'admin':
        for email, user_data in db.items():
            dni_decifrado = decrypt_aes(user_data.get('dni'), user_data.get('dni_nonce'), app.secret_key)
            print(f"DNI descifrado: {dni_decifrado}")
            user_data['dni'] = ofuscar_dni(dni_decifrado)
        return render_template('records.html',
                               users=db,
                               role=session.get('role'),
                               message=message,
                               darkmode=darkmode)
    else:
        if user is None:
            return render_template('records.html',
                                   users={},
                                   error="Usuario no encontrado",
                                   message=message,
                                   darkmode=darkmode)
        dni_decifrado = decrypt_aes(user.get('dni'), user.get('dni_nonce'), app.secret_key)
        user['dni'] = ofuscar_dni(dni_decifrado)
        return render_template('records.html',
                               users={user_email: user},
                               error=None,
                               message=message,
                               darkmode=darkmode)


@app.route('/update_user/<email>', methods=['POST'])
def update_user(email):
    # Leer la base de datos de usuarios
    db = read_db("db.txt")

    username = request.form['username']
    dni = request.form['dni']
    dob = request.form['dob']
    nombre = request.form['nombre']
    apellido = request.form['apellido']
    darkmode = 'dark' if 'darkmode' in request.form else 'light'
    errores = []

    if not validate_dob(dob):
        errores.append("Fecha de nacimiento inválida")
    if not validate_dni(dni):
        errores.append("DNI inválido")
    if not validate_user(username):
        errores.append("Usuario inválido")
    if not validate_name(nombre):
        errores.append("Nombre inválido")
    if not validate_name(apellido):
        errores.append("Apellido inválido")

    if errores:
        return render_template('edit_user.html',
                               user_data=db[email],
                               email=email,
                               error=errores)
    dni_cifrado, dni_nonce = encrypt_aes(normalize_input(dni), app.secret_key)

    db[email]['username'] = normalize_input(username)
    db[email]['nombre'] = normalize_input(nombre)
    db[email]['apellido'] = normalize_input(apellido)
    db[email]['dni'] = dni_cifrado
    db[email]['dni_nonce'] = dni_nonce
    db[email]['dob'] = normalize_input(dob)

    write_db("db.txt", db)
    resp = make_response(redirect(url_for('read_record', message="Información actualizada correctamente")))
    resp.set_cookie('darkmode', darkmode, secure=True, httponly=True, samesite='Lax')

    # Redirigir al usuario a la página de records con un mensaje de éxito
    return resp

@app.route('/api/delete_user/<email>', methods=['GET'])
def delete_user(email):

    if session.get('role') == 'admin':
        db = read_db("db.txt")

        if email not in db:
            return redirect(url_for('read_record', message="Usuario no encontrado"))

        del db[email]

        write_db("db.txt", db)

        return redirect(url_for('read_record', message="Usuario eliminado"))
    else:
        return redirect(url_for('read_record', message="No autorizado"))

# Endpoint para depósito
@app.route('/api/deposit', methods=['POST'])
def api_deposit():
    if 'email' not in session:
        # Redirigir a la página de inicio de sesión si el usuario no está autenticado
        error_msg = "Por favor, inicia sesión para acceder a esta página."
        return render_template('login.html', error=error_msg)

    deposit_balance = request.form['balance']
    deposit_email = session.get('email')

    db = read_db("db.txt")
    transactions = read_db("transaction.txt")

    # Verificamos si el usuario existe
    if deposit_email in db:
        # Guardamos la transacción
        transaction = {"balance": deposit_balance, "type": "Deposit", "timestamp": str(datetime.now())}

        # Verificamos si el usuario tiene transacciones previas
        if deposit_email in transactions:
            transactions[deposit_email].append(transaction)
        else:
            transactions[deposit_email] = [transaction]
        write_db("transaction.txt", transactions)

        return redirect(url_for('customer_menu', message="Depósito exitoso"))

    return redirect(url_for('customer_menu', message="Email no encontrado"))


# Endpoint para retiro
@app.route('/api/withdraw', methods=['POST'])
def api_withdraw():
    email = session.get('email')
    amount = float(request.form['balance'])
    password =normalize_input(request.form['password'])

    if amount <= 0:
        return redirect(url_for('customer_menu',
                                message="La cantidad a retirar debe ser positiva",
                                error=True))
    
    db = read_db("db.txt")
    transactions = read_db("transaction.txt")
    current_balance = sum(float(t['balance']) for t in transactions.get(email, []))

    #Contraseña
    password_db = db[email]["password"]
    salt_db = db[email]["password_salt"]

    if not compare_salt(password, password_db, salt_db):
        return redirect(url_for('customer_menu',
                                message="Contraseña incorrecta",
                                error=True))

    if amount > current_balance:
        return redirect(url_for('customer_menu',
                                message="Saldo insuficiente para retiro",
                                error=True))

    transaction = {"balance": -amount, "type": "Withdrawal", "timestamp": str(datetime.now())}

    if email in transactions:
        transactions[email].append(transaction)
    else:
        transactions[email] = [transaction]

    write_db("transaction.txt", transactions)

    return redirect(url_for('customer_menu',
                            message="Retiro exitoso",
                            error=False))
