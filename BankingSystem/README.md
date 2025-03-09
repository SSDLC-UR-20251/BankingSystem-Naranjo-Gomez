# 💻 Desarrollo Seguro en Aplicaciones Bancarias

## 🏛 Universidad del Rosario - 2025 - 1

En este ejercicio se abordarán múltiples aspectos de seguridad en una aplicación bancaria, incluyendo el tratamiento de datos confidenciales, autenticación en operaciones sensibles y manejo de sesiones. 

---

## 1️⃣ Tratamiento de Datos Restringidos

### 🔐 Ofuscación y Cifrado de Datos Sensibles

Para garantizar la privacidad de los datos almacenados y visualizados en la aplicación, se implementarán los siguientes controles:

- **Cédula**: 
  - En la vista del cliente autenticado, mostrar solo los últimos 4 dígitos. Ejemplo: `****1377`.
  - En la base de datos, debe almacenarse cifrada.


**Tips de Implementación**:
1. **Modificar la base de datos** para almacenar la cédula cifrada y el nonce con la que se realice el cifrado. La llave para cifrar puede ser la misma para todos los usuarios, o generar una nueva en cada login, si se decide este último método, deberán almacenar la llave también. 
2. **Actualizar la lógica de visualización** se deberá descifrar el dni almacenado, luego ofuscarlo mostrando solo los últimos 4 dígitos para posteriormente renderizarlo en la vista /records.
3. **Realizar pruebas** para verificar que los datos en reposo están cifrados y que la visualización funciona correctamente.

---

## 2️⃣ Seguridad en la Extracción de Dinero

Para fortalecer la seguridad en el endpoint `/withdraw`, se agregará autenticación secundaria:

**Tips de Implementación**:
1. **Modificar la vista /withdraw** para agregar un campo donde el usuario deba ingresar su contraseña antes de realizar un retiro.
2. **Actualizar el api** para validar que la contraseña ingresada coincide con la almacenada en la base de datos (al igual como lo hacemos en el login).
3. **Si la validación es exitosa**, permitir la extracción.
4. **Si la validación es incorrecta**, mostrar un mensaje de error y rechazar la operación.

---

## 3️⃣ Manejo de Sesiones Seguras

Estas funciones están enfocadas en mejorar la seguridad de la aplicación, asegurando un correcto manejo de sesiones:

### 🔑 1. Control de Sesión con Roles

- **Validar la sesión activa en cada solicitud**.
- **Verificar la existencia de la sesión del usuario** antes de conceder acceso a cualquier endpoint.
- **Si la sesión no es válida**, redirigir al usuario a la página de login.

### 🚪 2. Implementar Cierre de Sesión Seguro

- **Crear una ruta `/logout`** que elimine todos los datos de sesión y redirija al usuario a la página de login.
- **Asegurar que al eliminar un usuario**, su sesión también sea eliminada para evitar accesos no autorizados.

### ⏳ 3. Expiración de Sesión

- **Configurar la sesión para expirar después de 5 minutos de inactividad**.
- **Usar `session.permanent = True` y definir el tiempo de vida** con:
  ```python
  app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=5)
  ```
- **Implementar validación global** en cada solicitud usando `@before_request`.
- **Si la sesión ha expirado**, redirigir al usuario al login.

---

## 4️⃣ 4. Personalización de la Interfaz (Modo Oscuro)

- **Modificar la vista /edit_user** agregando un checkbox en la configuración de usuario para activar o desactivar el modo oscuro.
- **Actualizar el API** para almacenar la preferencia en una cookie. (no olviden agregar las flags de seguridad)
- **Modificar las vistas** para que la interfaz refleje la preferencia almacenada en la cookie.
- **Aplicar la configuración a todas las páginas**.
- **Incluir los estilos y scripts necesarios en las vistas**:
  ```html
  <html lang="en" data-bs-theme="{{ 'dark' if darkmode == 'dark' else 'light' }}">
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet"
        integrity="sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH"
        crossorigin="anonymous">
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"
        integrity="sha384-YvpcrYf0tY3lHB60NNkmXc5s9fDVZLESaAA55NDzOxhy9GkcIdslK1eN7N6jIeHz"
        crossorigin="anonymous"></script>
  ```

---

## 📌 Instrucciones de Entrega

1. **Subir los cambios a una nueva rama** `feature/security-improvements`.
2. **Asegurar que todas las funcionalidades han sido implementadas y probadas**.
3. **Crear un Pull Request** con la descripción de los cambios realizados.
4. **Entregar la URL del pull request en e-aulas**.

