// Jafet Uribe Ramirez
require('dotenv').config();
const express = require("express");
const admin = require("firebase-admin");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt"); // Importar bcrypt para el hash de contraseñas

const app = express();
const port = 5000;

// Inicializar Firebase Admin con credenciales
const serviceAccount = require("./Credenciales.json");

if (!admin.apps.length) {
  try {
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount),
    });
  } catch (error) {
    console.error("Error al inicializar Firebase Admin:", error);
  }
} else {
  admin.app(); // Si ya se ha inicializado, usa la instancia existente
}

const db = admin.firestore();

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// 🔹 Endpoint para registrar usuario con contraseña hasheada
app.post("/registro", async (req, res) => {
  const { email, username, password } = req.body;

  if (!email || !username || !password) {
    return res.status(400).json({ message: "Todos los campos son obligatorios" });
  }

  try {
    // Verificar si el usuario ya existe en Firestore dentro de la colección "Users"
    const userSnapshot = await db.collection("Users").where("username", "==", username).get();
    if (!userSnapshot.empty) {
      return res.status(400).json({ message: "El usuario ya está registrado" });
    }

    const emailSnapshot = await db.collection("Users").where("email", "==", email).get();
    if (!emailSnapshot.empty) {
      return res.status(400).json({ message: "El correo ya está registrado" });
    }

    // Hashear la contraseña antes de guardarla
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Obtener el siguiente número de documento (ID secuencial)
    const usersSnapshot = await db.collection("Users").get();
    const nextId = usersSnapshot.size + 1;  // Esto asegura que el ID sea único e incremental

    // Crear el objeto con los datos del usuario
    const userData = {
      username,
      email,
      password: hashedPassword, // Guardamos el hash, no la contraseña en texto plano
      role: 2, // Rol por defecto
      last_login: admin.firestore.FieldValue.serverTimestamp(),
    };

    // Imprimir el objeto en la consola antes de guardarlo
    console.log("Datos del usuario a guardar:", userData);

    // Guardar el usuario en Firestore con el ID generado secuencialmente
    const userRef = db.collection("Users").doc(`${nextId}`);
    await userRef.set(userData);

    res.status(200).json({ message: "Usuario registrado correctamente" });
  } catch (error) {
    console.error("Error en el registro de usuario:", error);
    res.status(500).json({ message: "Error al registrar usuario", error: error.message });
  }
});

// 🔹 Endpoint para login con comparación de hash
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: "Todos los campos son obligatorios" });
  }

  try {
    const userSnapshot = await db.collection("Users").where("username", "==", username).get();

    if (userSnapshot.empty) {
      return res.status(404).json({ message: "Usuario no encontrado" });
    }

    const userDoc = userSnapshot.docs[0];
    const userData = userDoc.data();

    const isPasswordValid = await bcrypt.compare(password, userData.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: "Credenciales incorrectas" });
    }

    // Actualiza el campo `last_login` con la marca de tiempo del servidor
    await db.collection("Users").doc(userDoc.id).update({
      last_login: admin.firestore.FieldValue.serverTimestamp(),
    });

    const token = jwt.sign(
      { uid: userDoc.id, username: userData.username, role: userData.role },
      process.env.JWT_SECRET,
      { expiresIn: "10m" }
    );

    res.status(200).json({ message: "Inicio de sesión exitoso", token });
    console.log("Token: ", token);
  } catch (error) {
    res.status(500).json({ message: "Error al iniciar sesión", error: error.message });
  }
});



const authenticateToken = (req, res, next) => {
  const token = req.headers["authorization"]?.split(" ")[1]; // Extraer el token después de "Bearer "

  if (!token) {
    return res.status(401).json({ message: "Token no proporcionado" });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      if (err.name === "TokenExpiredError") {
        console.log("Token expirado");
      } else {
        console.log("Token inválido o error en la verificación");
      }
      return res.status(403).json({ message: "Token expirado o inválido" });
    }

    console.log("Usuario autenticado:", decoded); // Verifica que el token contiene los datos esperados
    req.user = decoded; // Asegura que req.user se está asignando correctamente
    next();
  });
};

// 🔹 Ruta protegida que requiere un token válido
app.get("/protected", authenticateToken, (req, res) => {
  res.status(200).json({ message: "Acceso permitido", user: req.user });
});

app.post("/tasks", authenticateToken, async (req, res) => {
  const { nameTask, category, description, deadline, status } = req.body;
 
  if (!nameTask || !category || !description || !deadline || !status) {
    return res.status(400).json({ message: "Todos los campos son obligatorios" });
  }

  try {
    // Obtener el siguiente ID secuencial
    const tasksSnapshot = await db.collection("Tasks").get();
    const nextId = tasksSnapshot.size + 1;

    // Crear el objeto de tarea
    const taskData = {
      nameTask,
      category,
      description,
      deadline: new Date(deadline), // Convertir a fecha
      status,
      uid: req.user.uid,
      create: admin.firestore.FieldValue.serverTimestamp(), // Timestamp automático

    };

    // Guardar la tarea en Firestore
    const taskRef = db.collection("Tasks").doc(`${nextId}`);
    await taskRef.set(taskData);
    console.log("Tarea registrada correctamente");
    res.status(200).json({ message: "Tarea registrada correctamente" });
  } catch (error) {
    console.error("Error al registrar la tarea:", error);
    res.status(500).json({ message: "Error al registrar tarea", error: error.message });
  }
});
app.get("/obtener-tasks", authenticateToken, async (req, res) => {
  try {
    const { uid } = req.user; // Obtiene el UID del usuario autenticado
    const tasksSnapshot = await db.collection("Tasks").where("uid", "==", uid).get();

    const tasks = tasksSnapshot.docs.map((doc) => ({
      id: doc.id,
      ...doc.data(),
    }));

    res.status(200).json(tasks);
  } catch (error) {
    console.error("Error al obtener tareas:", error);
    res.status(500).json({ message: "Error al obtener tareas", error: error.message });
  }
});


app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
