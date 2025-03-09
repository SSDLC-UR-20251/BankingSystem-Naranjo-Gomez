from datetime import datetime,timedelta, timezone
import time
from app.validation import *
from app.reading import *
from flask import request, jsonify, redirect, url_for, render_template, session, make_response, g
from app import app
from app.encryption import *

login_attempts = {}
MAX_ATTEMPTS = 3
BLOCK_TIME = 300  # 5 minutos en segundos
app.secret_key = 'your_secret_key'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=5)


@app.before_request
def validar_sesion():
    if 'email' in session:
        last_activity = session.get('last_activity')

        if last_activity:
            last_activity_time = datetime.fromisoformat(last_activity)
            if datetime.now(timezone.utc) - last_activity_time > app.config['PERMANENT_SESSION_LIFETIME']:
                session.clear()
                return redirect(url_for('login', message="Sesión expirada por inactividad. Inicia sesión nuevamente."))

        # Si la sesión sigue activa, actualizar la última actividad
        session['last_activity'] = datetime.now(timezone.utc).isoformat()

    # Obtener la preferencia de modo oscuro desde la cookie
    darkmode = request.cookies.get('darkmode', 'light')

    # Pasar la preferencia del modo oscuro a las vistas
    g.darkmode = darkmode

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
    # Validaciones
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
    db = read_db("db.txt")
    db[email] = {
        'nombre': normalize_input(nombre),
        'apellido': normalize_input(apellido),
        'username': normalize_input(username),
        'password': hashed_pwd,
        "password_salt": salt,
        "dni": dni,
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
    user_dni = db.get(email)["dni"]
    dni_ofuscado = ofuscar_dni(user_dni)
    message = request.args.get('message', '')
    error = request.args.get('error', 'false').lower() == 'true'
    return render_template('customer_menu.html',
                           message=message,
                           nombre=db.get(email)['nombre'],
                           balance=current_balance,
                           last_transactions=last_transactions,
                           error=error,
                           dni = dni_ofuscado)


# Endpoint para leer un registro
@app.route('/records', methods=['GET'])
def read_record():

    db = read_db("db.txt")
    user_email = session.get('email')
    user = db.get(user_email, None)
    message = request.args.get('message', '')
    # Si el usuario es admin, mostrar todos los registros con DNI ofuscado
    for email, user_data in db.items():
        user_data['dni'] = ofuscar_dni(user_data['dni'])
    if session.get('role') == 'admin':
        return render_template('records.html',
                               users=db,
                               role=session.get('role'),
                               message=message)
    else:
        return render_template('records.html',
                               users={user_email: user},
                               error=None,
                               message=message)


@app.route('/update_user/<email>', methods=['POST'])
def update_user(email):
    # Leer la base de datos de usuarios
    db = read_db("db.txt")

    username = request.form['username']
    dni = request.form['dni']
    dob = request.form['dob']
    nombre = request.form['nombre']
    apellido = request.form['apellido']
    darkmode = 'dark' if 'darkmode' in request.form else 'light'  # Detectar el valor del checkbox

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
        return render_template('edit_user.html', user_data=db[email], email=email, error=errores)

    db[email]['username'] = normalize_input(username)
    db[email]['nombre'] = normalize_input(nombre)
    db[email]['apellido'] = normalize_input(apellido)
    db[email]['dni'] = dni
    db[email]['dob'] = normalize_input(dob)

    # Guardar la preferencia del modo oscuro en una cookie
    resp = make_response(redirect(url_for('read_record', message="Información actualizada correctamente")))

    # Establecer la cookie para el modo oscuro
    resp.set_cookie('darkmode', darkmode, max_age=365*24*60*60)  # Guardar la preferencia por un año

    write_db("db.txt", db)
    
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
    if 'email' not in session:
        return redirect(url_for('login'))

    email = session['email']
    amount = float(request.form['balance'])
    password = normalize_input(request.form['password'])

    if amount <= 0:
        return redirect(url_for('customer_menu', message="La cantidad a retirar debe ser positiva", error=True))

    db = read_db("db.txt")
    transactions = read_db("transaction.txt")
    current_balance = sum(float(t['balance']) for t in transactions.get(email, []))
    stored_password_hash = db[email]["password"]
    stored_password_salt = db[email]["password_salt"]

    if compare_salt(password, stored_password_hash, stored_password_salt):
        if amount > current_balance:
            return redirect(url_for('customer_menu', message="Saldo insuficiente para retiro", error=True))

        # Registrar la transacción de retiro
        transaction = {"balance": -amount, "type": "Withdrawal", "timestamp": str(datetime.now())}
        transactions.setdefault(email, []).append(transaction)
        write_db("transaction.txt", transactions)

        return redirect(url_for('customer_menu', message="Retiro exitoso", error=False))
    else:
        return redirect(url_for('customer_menu', message="Contraseña incorrecta. Intenta nuevamente.", error=True))


@app.route('/logout')
def logout():
    session.clear()  # Eliminar todos los datos de sesión
    return redirect(url_for('login'))