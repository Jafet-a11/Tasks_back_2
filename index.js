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
      role: 1, // Rol por defecto
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
      { uid: userDoc.id, username: userData.username, role: userData.role, group_id:userData.group_id },
      process.env.JWT_SECRET,
      { expiresIn: "10m" }
    );

    res.status(200).json({ message: "Inicio de sesión exitoso", token , userData});
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

    // Verifica que el token contiene los datos esperados
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

app.post("/tasksGroup", authenticateToken, async (req, res) => {
  const { nameTask, category, description, deadline, status, assignedUser, username } = req.body;

  if (!nameTask || !category || !description || !deadline || !status || !assignedUser || !username) {
    return res.status(400).json({ message: "Todos los campos son obligatorios" });
  }

  try {
    // Obtener el siguiente ID secuencial
    const tasksSnapshot = await db.collection("Tasks").get();
    const nextId = tasksSnapshot.size + 1;

    // Consultar datos del usuario asignado
    const userRef = db.collection("Users").doc(`${assignedUser}`);
    const userDoc = await userRef.get();

    let assignedUsername = null;
    let group_id = null;
    let group_name = null; // Nombre del grupo

    if (userDoc.exists) {
      const userData = userDoc.data();
      assignedUsername = userData.username; // Obtener el username del usuario asignado

      if (userData.group_id) {
        group_id = userData.group_id;

        // Consultar el nombre del grupo en la colección "Groups"
        const groupRef = db.collection("Groups").doc(`${group_id}`);
        const groupDoc = await groupRef.get();

        if (groupDoc.exists) {
          group_name = groupDoc.data().name; // Obtener el nombre del grupo
        }
      }
    } else {
      return res.status(404).json({ message: "Usuario asignado no encontrado" });
    }

    // Crear el objeto de tarea
    const taskData = {
      nameTask,
      category,
      description,
      deadline: new Date(deadline), // Convertir a fecha
      status,
      uid: req.user.uid,
      create: admin.firestore.FieldValue.serverTimestamp(), // Timestamp automático
      assignedUser, // ID del usuario asignado
      assignedUsername, // Username del usuario asignado
      assigned_by: username, // Username de quien asigna la tarea
      group_id, // ID del grupo si lo tiene
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
    const tasksSnapshot = await db
      .collection("Tasks")
      .where("uid", "==", uid) // Filtra por el UID del usuario
      .get();

    // Filtramos las tareas que no tienen 'group_id' o que 'group_id' es null
    const tasks = tasksSnapshot.docs
      .map((doc) => ({
        id: doc.id,
        ...doc.data(),
      }))
      .filter((task) => !task.group_id); // Filtra las tareas donde group_id es undefined o null

    res.status(200).json(tasks);
  } catch (error) {
    console.error("Error al obtener tareas:", error);
    res.status(500).json({ message: "Error al obtener tareas", error: error.message });
  }
});



app.get("/obtener-tasks-group", authenticateToken, async (req, res) => {
  try {
    console.log(req.user); // Verifica que req.user tenga el group_id
    const { group_id } = req.user; // Obtiene el group_id del usuario autenticado
    if (!group_id) {
      return res.status(400).json({ message: "No se encontró el group_id del usuario" });
    }

    const tasksSnapshot = await db.collection("Tasks").where("group_id", "==", group_id).get();

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



app.post("/editarTarea", authenticateToken, async (req, res) => {
  const { id, nameTask, category, description, deadline, status } = req.body;

  if (!id || !nameTask || !category || !description || !deadline || !status) {
    return res.status(400).json({ message: "Todos los campos son obligatorios" });
  }

  try {
    // Verificar si la tarea existe
    const taskRef = db.collection("Tasks").doc(id);
    const taskDoc = await taskRef.get();

    if (!taskDoc.exists) {
      return res.status(404).json({ message: "Tarea no encontrada" });
    }

    // Convertir deadline a un objeto Date (si es necesario)
    const parsedDeadline = deadline ? admin.firestore.Timestamp.fromDate(new Date(deadline)) : null; // Convierte la fecha a un objeto Date

    // Crear el objeto de actualización
    const taskData = {
      nameTask,
      category,
      description,
      deadline: parsedDeadline,   // Usamos la fecha convertida aquí
      status,
    };

    // Actualizar la tarea en Firestore
    await taskRef.update(taskData);
    console.log("Tarea actualizada correctamente");
    res.status(200).json({ message: "Tarea actualizada correctamente" });
  } catch (error) {
    console.error("Error al actualizar la tarea:", error);
    res.status(500).json({ message: "Error al actualizar tarea", error: error.message });
  }
});

app.post("/editarTareaGroup", authenticateToken, async (req, res) => {
  const { id, nameTask, category, description, deadline, status, assignedUser } = req.body;  // Agregar el usuario asignado


  if (!id || !nameTask || !category || !description || !deadline || !status || !assignedUser) {
    return res.status(400).json({ message: "Todos los campos son obligatorios" });
  }

  try {
    // Verificar si la tarea existe
    const taskRef = db.collection("Tasks").doc(id);
    const taskDoc = await taskRef.get();

    if (!taskDoc.exists) {
      return res.status(404).json({ message: "Tarea no encontrada" });
    }

    // Convertir deadline a un objeto Date (si es necesario)
    const parsedDeadline = deadline ? admin.firestore.Timestamp.fromDate(new Date(deadline)) : null; // Convierte la fecha a un objeto Date

    // Crear el objeto de actualización
    const taskData = {
      nameTask,
      category,
      description,
      deadline: parsedDeadline,   // Usamos la fecha convertida aquí
      status,
      assignedUser,
    };

    // Actualizar la tarea en Firestore
    await taskRef.update(taskData);
    console.log("Tarea actualizada correctamente");
    res.status(200).json({ message: "Tarea actualizada correctamente" });
  } catch (error) {
    console.error("Error al actualizar la tarea:", error);
    res.status(500).json({ message: "Error al actualizar tarea", error: error.message });
  }
});

app.delete("/eliminar-task/:id", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params; // Obtiene el ID de la tarea de los parámetros de la URL
    const { uid } = req.user; // Obtiene el UID del usuario autenticado

    const taskRef = db.collection("Tasks").doc(id);
    const taskDoc = await taskRef.get();

    if (!taskDoc.exists) {
      return res.status(404).json({ message: "Tarea no encontrada" });
    }

    // Verifica que la tarea pertenezca al usuario autenticado
    if (taskDoc.data().uid !== uid) {
      return res.status(403).json({ message: "No tienes permiso para eliminar esta tarea" });
    }

    await taskRef.delete();
    res.status(200).json({ message: "Tarea eliminada correctamente" });
  } catch (error) {
    console.error("Error al eliminar la tarea:", error);
    res.status(500).json({ message: "Error al eliminar la tarea", error: error.message });
  }
});

app.post("/crear-grupo", authenticateToken, async (req, res) => {
  try {
    const { username, role, uid } = req.user; // Aseguramos que el ID de usuario se obtenga correctamente
    const { nameGroup, members } = req.body; // Lista de IDs de usuarios

    console.log("ID del usuario autenticado:", uid);
    console.log("Usuarios a agregar al grupo:", members);

    if (!nameGroup) {
      return res.status(400).json({ message: "El nombre del grupo es obligatorio" });
    }

    if (role !== 2 && role !== 3) {
      return res.status(403).json({ message: "No tienes permiso para crear grupos" });
    }

    const existingGroup = await db.collection("Groups").where("nameGroup", "==", nameGroup).get();
    if (!existingGroup.empty) {
      return res.status(400).json({ message: "El grupo ya existe" });
    }

    const metaRef = db.collection("MetaData").doc("groupCounter");

    let newGroupId;
    await db.runTransaction(async (transaction) => {
      const metaDoc = await transaction.get(metaRef);
      newGroupId = metaDoc.exists ? metaDoc.data().lastGroupId + 1 : 1;
      transaction.set(metaRef, { lastGroupId: newGroupId }, { merge: true });
    });

    const newGroup = {
      id: newGroupId,
      created_by: username,
      nameGroup,
      created_at: new Date().toISOString(),
    };

    await db.collection("Groups").doc(newGroupId.toString()).set(newGroup);
    console.log("Grupo creado con ID:", newGroupId);

    if (members && Array.isArray(members) && members.length > 0) {
      const batch = db.batch();

      for (const userId of members) {
        const userRef = db.collection("Users").doc(userId);
        const userDoc = await userRef.get();

        if (userDoc.exists) {
          console.log(`Actualizando usuario ${userId} con grupo ${newGroupId}`);
          batch.update(userRef, { group_id: newGroupId, group_name: nameGroup });
        } else {
          console.log(`Usuario con ID ${userId} no encontrado en la base de datos.`);
        }
      }

      await batch.commit();
      console.log("Usuarios actualizados correctamente.");
    } else {
      console.log("No se enviaron usuarios válidos para actualizar.");
    }

    res.status(201).json({ message: "Grupo creado y usuarios actualizados", group: newGroup });
  } catch (error) {
    console.error("Error al crear grupo:", error);
    res.status(500).json({ message: "Error al crear grupo", error: error.message });
  }
});



// Obtener todos los grupos
app.get("/obtener-groups", authenticateToken, async (req, res) => {
  try {
    const groupsSnapshot = await db.collection("Groups").get();
    const groups = groupsSnapshot.docs.map((doc) => ({ id: doc.id, ...doc.data() }));
    res.status(200).json(groups);
  } catch (error) {
    console.error("Error al obtener grupos:", error);
    res.status(500).json({ message: "Error al obtener grupos", error: error.message });
  }
});
app.get("/obtener-usuarios", async (req, res) => {
  try {
    const usersRef = db.collection("Users"); // Cambia "users" por el nombre de tu colección
    const snapshot = await usersRef.get();

    if (snapshot.empty) {
      return res.status(404).json({ message: "No se encontraron usuarios" });
    }

    const users = snapshot.docs.map((doc) => ({
      id: doc.id,
      ...doc.data(),
    }));

    res.json(users); // Devuelve los usuarios
  } catch (error) {
    console.error("Error al obtener los usuarios:", error);
    res.status(500).json({ message: "Error al obtener los usuarios" });
  }
});

app.post("/updateTaskStatus/:taskId",authenticateToken, async (req, res) => {
  try {
    const { taskId } = req.params;
    const { status } = req.body;

    if (!status) {
      return res.status(400).json({ error: "El campo status es requerido." });
    }

    const taskRef = db.collection("Tasks").doc(taskId);
    await taskRef.update({ status });
    console.log("Tarea actualizacion:" , "id: ", taskId , "Estatus: ", status);
    res.status(200).json({ message: "Estado actualizado con éxito." });
  } catch (error) {
    res.status(500).json({ error: "Error al actualizar el estado.", details: error.message });
  }
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
