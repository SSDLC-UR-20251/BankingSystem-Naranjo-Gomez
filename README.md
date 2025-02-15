# 📌 Laboratorio: Validación y Actualización de Usuarios en Flask  

## 📝 Descripción  
Para este laboratorio, se ha creado una aplicación sencilla que permite a los usuarios **registrar y visualizar información** mediante un formulario y una tabla de datos.  

La aplicación está construida con **Flask** y consta de las siguientes partes clave:  

- **Archivos HTML**:  
  - `form.html`: Presenta la interfaz para que los usuarios ingresen su información.  
  - `customer_menu.html`: Muestra el menu principal del usuario.
  - `records.html`: Muestra todos los registros en una tabla.  
  - `index.html`: Muestra la pagina principal para todos los usuarios
  - `login.html`: Muestra formulario login

- **Archivo de rutas (`routes.py`)**: Permite renderizar la interfaz HTML principal.  
- **Archivo de API**: Contiene toda la lógica para los endpoints de registro y visualización.  
- **Base de datos**: Simple archivo `.txt` donde se almacena la información registrada.  

---

## 🎯 Objetivo del Laboratorio  
Se debe **complementar la aplicación** para que valide los datos ingresados y permita la actualización de información.  

---

## ✅ **Tareas a Realizar**  

### 1️⃣ Validación de Usuario  
- El **nombre de usuario** solo puede contener **caracteres alfabéticos y el punto (`.`)**.  
- Ejemplo válido: `sara.palacios`.  

### 2️⃣ Validación de Contraseña  
Según las **políticas de seguridad de la Universidad del Rosario**, una contraseña debe cumplir con:  
- **Al menos una letra minúscula, una letra mayúscula y un número**.  
- **Al menos un carácter especial requerido**: `# * @ $ % & - ! + = ?`.  
- **Longitud mínima:** 8 caracteres.  
- **Longitud máxima:** 35 caracteres.  

### 3️⃣ Validación de Correo Electrónico  
- Se debe asegurar que el **dominio del correo electrónico** sea: `@urosario.edu.co`.  

### 4️⃣ Validación de Fecha de Nacimiento  
- Solo se pueden registrar usuarios **mayores de 16 años**.  

### 5️⃣ Validación de Documento de Identificación  
- Debe ser **numérico** y tener **máximo 10 dígitos**.  
- Debe **iniciar con "1000000000"**.  

---

## 🔧 **Nueva Funcionalidad: Endpoint de Actualización**  
Actualmente, la web permite el **registro y visualización de datos** a través de las rutas `/` y `/records`.  

### 🔄 **Requerimiento Adicional**  
Se debe **crear un nuevo endpoint `PUT`** que permita a un usuario **con un correo electrónico fijo** actualizar su información:  
- **Nombre de usuario**  
- **Contraseña**  
- **Fecha de nacimiento**  
- **Número de documento**  

### 🛠️ **Requisitos para la Actualización**  
- Los datos deben pasar **nuevamente** por las validaciones establecidas anteriormente.  
- Se debe verificar que el usuario que realiza la solicitud **existe en la base de datos**.  
