// Importar dependencias
const express = require("express");
const cors = require("cors");
const axios = require("axios");
const admin = require("firebase-admin");
const { GoogleAuth } = require("google-auth-library");
require("dotenv").config();

// Configurar Firebase Admin SDK
const firebaseServiceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_KEY);
admin.initializeApp({
  credential: admin.credential.cert(firebaseServiceAccount),
});
console.log("Firebase Admin SDK inicializado correctamente.");

// Configurar credenciales de Dialogflow
const dialogflowCredentials = JSON.parse(process.env.GOOGLE_APPLICATION_CREDENTIALS);

// Crear una instancia de Express
const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// Puerto del servidor
const PORT = process.env.PORT || 5000;

// URL base de Dialogflow
const DIALOGFLOW_API_URL = `https://dialogflow.googleapis.com/v2/projects/${process.env.DIALOGFLOW_PROJECT_ID}/agent/sessions/`;

// Configurar Google Auth para Dialogflow
const googleAuth = new GoogleAuth({
  credentials: dialogflowCredentials,
  scopes: ["https://www.googleapis.com/auth/dialogflow"],
});

// Función para obtener un token de acceso para Dialogflow
const getAccessToken = async () => {
  try {
    const client = await googleAuth.getClient();
    const token = await client.getAccessToken();
    return token.token;
  } catch (error) {
    console.error("Error al obtener el token de acceso:", error.message);
    throw new Error("No se pudo obtener el token de acceso para Dialogflow.");
  }
};

// Manejar las solicitudes del chatbot
app.post("/chatbot", async (req, res) => {
  const { sessionId, message } = req.body;

  // Validar que los datos requeridos estén presentes
  if (!sessionId || !message) {
    return res.status(400).json({ error: "Falta sessionId o message en la solicitud." });
  }

  try {
    // Obtener el token de acceso para Dialogflow
    const token = await getAccessToken();

    // Enviar la solicitud a Dialogflow
    const response = await axios.post(
      `${DIALOGFLOW_API_URL}${sessionId}:detectIntent`,
      {
        queryInput: {
          text: {
            text: message,
            languageCode: "es",
          },
        },
      },
      {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      }
    );

    // Extraer la respuesta de Dialogflow
    const fulfillmentText = response.data.queryResult?.fulfillmentText;

    // Verificar si hay una respuesta válida
    if (!fulfillmentText) {
      return res.status(500).json({ error: "Dialogflow no devolvió una respuesta válida." });
    }

    // Devolver la respuesta al frontend
    res.json({ response: fulfillmentText });
  } catch (error) {
    console.error("Error al comunicarse con Dialogflow:", error.message);
    console.error("Detalles del error:", error.response?.data);
    res.status(error.response?.status || 500).json({ error: "Error al comunicarse con Dialogflow" });
  }
});

// Middleware para verificar roles
const verifyRole = (allowedRoles) => {
  return async (req, res, next) => {
    try {
      // Obtener el token de autenticación del encabezado de la solicitud
      const idToken = req.headers.authorization?.split("Bearer ")[1];
      if (!idToken) {
        return res.status(401).json({ error: "Token no proporcionado." });
      }

      // Verificar el token con Firebase Authentication
      const decodedToken = await admin.auth().verifyIdToken(idToken);
      const uid = decodedToken.uid;

      // Obtener el rol del usuario desde Firestore
      const userDoc = await admin.firestore().collection("users").doc(uid).get();
      if (!userDoc.exists || !allowedRoles.includes(userDoc.data().role)) {
        return res.status(403).json({ error: "Acceso no autorizado." });
      }

      next();
    } catch (error) {
      console.error("Error al verificar el token:", error.message);
      res.status(401).json({ error: "Token inválido o expirado." });
    }
  };
};
// Rutas Publicas
// Ver el menú (página principal, clientes y meseros)
app.get("/menu", async (req, res) => {
  try {
    const menuSnapshot = await admin.firestore().collection("menu").get();
    const menu = menuSnapshot.docs
      .map((doc) => ({ id: doc.id, ...doc.data() }))
      .filter((item) => item.nombre && item.precio); // Filtrar elementos válidos

    res.json(menu);
  } catch (error) {
    console.error("Error al obtener el menú:", error.message);
    res.status(500).json({ error: "Error al obtener el menú." });
  }
});

// Ruta para crear un pedido (clientes y meseros)
app.post("/create-order", async (req, res) => {
  const { userId, items } = req.body;
  if (!userId || !items || !Array.isArray(items)) {
    return res.status(400).json({ error: "Datos inválidos para crear el pedido." });
  }

  try {
    // Calcular el total del pedido
    const total = items.reduce((sum, item) => sum + item.price * item.quantity, 0);

    // Guardar el pedido en Firestore con el campo "total"
    const orderRef = await admin.firestore().collection("orders").add({
      userId,
      items,
      total, 
      status: "pendiente",
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    res.json({ message: "Pedido creado con éxito.", orderId: orderRef.id });
  } catch (error) {
    console.error("Error al crear el pedido:", error.message);
    res.status(500).json({ error: "Error al crear el pedido." });
  }
});

// Obtener pedidos por usuario (clientes y meseros)
app.get("/user-orders/:userId", async (req, res) => {
  const { userId } = req.params;
  try {
    const ordersSnapshot = await admin
      .firestore()
      .collection("orders")
      .where("userId", "==", userId)
      .orderBy("createdAt", "desc")
      .get();

    const orders = await Promise.all(
      ordersSnapshot.docs.map(async (doc) => {
        const orderData = doc.data();

        // Obtener los nombres de los productos
        const itemsWithNames = await Promise.all(
          orderData.items.map(async (item) => {
            const productDoc = await admin.firestore().collection("menu").doc(item.productId).get();
            const productData = productDoc.data();
            return {
              productId: item.productId,
              productName: productData?.nombre || "Producto no disponible",
              quantity: item.quantity,
              price: item.price,
            };
          })
        );

        // Calcular el total del pedido
        const total = itemsWithNames.reduce((sum, item) => {
          const price = typeof item.price === "number" ? item.price : parseFloat(item.price);
          return sum + (price * item.quantity);
        }, 0);

        return {
          id: doc.id,
          items: itemsWithNames,
          status: orderData.status,
          total: total.toFixed(2),
          createdAt: orderData.createdAt.toDate().toLocaleString(),
        };
      })
    );

    res.json(orders);
  } catch (error) {
    console.error("Error al obtener los pedidos:", error.message);
    res.status(500).json({ error: "Error al obtener los pedidos." });
  }
});

// Ruta para registrar un nuevo cliente
app.post("/register", async (req, res) => {
  const { fullName, address, phone, email, password } = req.body;

  // Validar que todos los campos requeridos estén presentes
  if (!fullName || !address || !phone || !email || !password) {
    return res.status(400).json({ error: "Faltan campos obligatorios." });
  }

  try {
    // Crear usuario en Firebase Authentication
    const userRecord = await admin.auth().createUser({
      email,
      password,
    });

    // Guardar los datos adicionales del cliente en Firestore
    await admin.firestore().collection("users").doc(userRecord.uid).set({
      fullName,
      address,
      phone,
      email,
      role: "client", // Rol por defecto
    });

    res.json({ message: "Cliente registrado con éxito.", uid: userRecord.uid });
  } catch (error) {
    console.error("Error al registrar cliente:", error.message);
    res.status(500).json({ error: "Error al registrar cliente." });
  }
});

//---------------------------------Cocina------------------------------------------------------------
// Filtrar pedidos
app.get("/kitchen-orders", verifyRole(["kitchen"]), async (req, res) => {
  try {
    const pendingSnapshot = await admin.firestore().collection("orders").where("status", "==", "pendiente").get();
    const inProgressSnapshot = await admin.firestore().collection("orders").where("status", "==", "en-preparacion").get();
    const completedSnapshot = await admin.firestore().collection("orders").where("status", "==", "listo").get();

    // Función para agregar nombres de productos a los items
    const addProductNamesToOrders = async (snapshot) => {
      return await Promise.all(
        snapshot.docs.map(async (doc) => {
          const orderData = doc.data();
          const itemsWithNames = await Promise.all(
            orderData.items.map(async (item) => {
              const productDoc = await admin.firestore().collection("menu").doc(item.productId).get();
              const productData = productDoc.data();
              return {
                productId: item.productId,
                productName: productData?.nombre || "Producto no disponible",
                quantity: item.quantity,
                price: item.price,
              };
            })
          );
          return { id: doc.id, ...orderData, items: itemsWithNames };
        })
      );
    };

    const orders = {
      pendiente: await addProductNamesToOrders(pendingSnapshot),
      "en-preparacion": await addProductNamesToOrders(inProgressSnapshot),
      listo: await addProductNamesToOrders(completedSnapshot),
    };

    res.json(orders);
  } catch (error) {
    console.error("Error al obtener pedidos:", error.message);
    res.status(500).json({ error: "Error al obtener pedidos." });
  }
});

// Actualizar el estado de un pedido
app.post("/update-order-status", verifyRole(["kitchen"]), async (req, res) => {
  const { orderId, newStatus } = req.body;
  const allowedStatuses = ["pendiente", "en-preparacion", "listo"];
  if (!orderId || !newStatus || !allowedStatuses.includes(newStatus)) {
    return res.status(400).json({ error: "Falta orderId o newStatus inválido." });
  }
  try {
    const orderDoc = await admin.firestore().collection("orders").doc(orderId).get();
    if (!orderDoc.exists) {
      return res.status(404).json({ error: "El pedido no existe." });
    }
    await admin.firestore().collection("orders").doc(orderId).update({ status: newStatus });
    res.json({ message: "Estado del pedido actualizado." });
  } catch (error) {
    console.error("Error al actualizar el estado del pedido:", error.message);
    res.status(500).json({ error: "Error al actualizar el estado del pedido." });
  }
});

// Rutas Administrador
// Registrar un nuevo trabajador
app.post("/register-worker", verifyRole(["admin"]), async (req, res) => {
  const { email, password, role } = req.body;
  if (!email || !password || !role || !["kitchen", "waiter"].includes(role)) {
    return res.status(400).json({ error: "Falta email, password o role inválido." });
  }
  try {
    const userRecord = await admin.auth().createUser({ email, password });
    await admin.firestore().collection("users").doc(userRecord.uid).set({ email, role });
    res.json({ message: "Trabajador registrado con éxito.", uid: userRecord.uid });
  } catch (error) {
    console.error("Error al registrar trabajador:", error.message);
    res.status(500).json({ error: "Error al registrar trabajador." });
  }
});

// Consultar trabajadores
app.get("/workers", verifyRole(["admin"]), async (req, res) => {
  try {
    const kitchenSnapshot = await admin.firestore().collection("users").where("role", "==", "kitchen").get();
    const waiterSnapshot = await admin.firestore().collection("users").where("role", "==", "waiter").get();
    const workers = [
      ...kitchenSnapshot.docs.map((doc) => ({ id: doc.id, ...doc.data() })),
      ...waiterSnapshot.docs.map((doc) => ({ id: doc.id, ...doc.data() })),
    ];
    res.json(workers);
  } catch (error) {
    console.error("Error al obtener trabajadores:", error.message);
    res.status(500).json({ error: "Error al obtener trabajadores." });
  }
});

// Obtener lista de clientes
app.get("/clients", verifyRole(["admin"]), async (req, res) => {
  try {
    const usersSnapshot = await admin.firestore().collection("users").where("role", "==", "client").get();
    const clients = usersSnapshot.docs.map((doc) => ({
      id: doc.id,
      fullName: doc.data().fullName || "Nombre no disponible",
      address: doc.data().address || "Dirección no disponible",
      phone: doc.data().phone || "Teléfono no disponible",
      email: doc.data().email || "Correo no disponible",
    }));
    res.json(clients);
  } catch (error) {
    console.error("Error al obtener clientes:", error.message);
    res.status(500).json({ error: "Error al obtener clientes." });
  }
});

// Obtener historial de pedidos
app.get("/order-history", verifyRole(["admin"]), async (req, res) => {
  try {
    const ordersSnapshot = await admin.firestore().collection("orders").orderBy("createdAt", "desc").get();
    const orders = await Promise.all(
      ordersSnapshot.docs.map(async (doc) => {
        const orderData = doc.data();

        // Obtener el nombre y correo del cliente
        const userDoc = await admin.firestore().collection("users").doc(orderData.userId).get();
        const userData = userDoc.exists ? userDoc.data() : null;

        // Obtener los nombres de los productos
        const itemsWithNames = await Promise.all(
          orderData.items.map(async (item) => {
            const productDoc = await admin.firestore().collection("menu").doc(item.productId).get();
            const productData = productDoc.exists ? productDoc.data() : null;
            return {
              productId: item.productId,
              productName: productData?.nombre || "Producto no disponible",
              quantity: item.quantity,
              price: productData?.precio || 0,
            };
          })
        );

        // Calcular el total dinámicamente si no está presente
        const total =
          orderData.total ||
          itemsWithNames.reduce((sum, item) => sum + item.price * item.quantity, 0);

        // Formatear el total como un número con dos decimales
        const formattedTotal = typeof total === "number" ? total.toFixed(2) : "0.00";

        return {
          id: doc.id,
          clientName: userData?.fullName || "Nombre no disponible",
          clientEmail: userData?.email || "Correo no disponible",
          items: itemsWithNames,
          status: orderData.status || "Estado no disponible",
          total: formattedTotal,
          createdAt: orderData.createdAt.toDate().toLocaleString(),
        };
      })
    );

    res.json(orders);
  } catch (error) {
    console.error("Error al obtener historial de pedidos:", error.message);
    res.status(500).json({ error: "Error al obtener historial de pedidos." });
  }
});

// Ruta para actualizar un trabajador
app.post("/update-worker", verifyRole(["admin"]), async (req, res) => {
  const { workerId, email, password, role } = req.body;

  if (!workerId || !email || !role || !["kitchen", "waiter"].includes(role)) {
    return res.status(400).json({ error: "Faltan campos obligatorios o rol inválido." });
  }

  try {
    // Actualizar el correo electrónico en Firebase Authentication
    await admin.auth().updateUser(workerId, { email });

    // Si se proporciona una nueva contraseña, actualizarla también
    if (password) {
      await admin.auth().updateUser(workerId, { password });
    }

    // Actualizar el rol en Firestore
    await admin.firestore().collection("users").doc(workerId).update({
      email,
      role,
    });

    res.json({ message: "Trabajador actualizado con éxito." });
  } catch (error) {
    console.error("Error al actualizar trabajador:", error.message);
    res.status(500).json({ error: "Error al actualizar trabajador." });
  }
});

// Ruta para eliminar un trabajador
app.post("/delete-worker", verifyRole(["admin"]), async (req, res) => {
  const { workerId } = req.body;

  if (!workerId) {
    return res.status(400).json({ error: "Falta workerId en la solicitud." });
  }

  try {
    // Eliminar el usuario de Firebase Authentication
    await admin.auth().deleteUser(workerId);

    // Eliminar el usuario de Firestore
    await admin.firestore().collection("users").doc(workerId).delete();

    res.json({ message: "Trabajador eliminado con éxito." });
  } catch (error) {
    console.error("Error al eliminar trabajador:", error.message);
    res.status(500).json({ error: "Error al eliminar trabajador." });
  }
});

//-----------------------------------Cliente-----------------------------------------------------
// Ruta para agregar un producto al carrito del cliente
app.post("/add-to-cart", verifyRole(["client"]), async (req, res) => {
  const { userId, productId } = req.body;

  if (!userId || !productId) {
    return res.status(400).json({ error: "Falta userId o productId." });
  }

  try {
    // Obtener el producto del menú
    const productDoc = await admin.firestore().collection("menu").doc(productId).get();
    if (!productDoc.exists) {
      return res.status(404).json({ error: "Producto no encontrado." });
    }

    const product = productDoc.data();

    // Verificar si el carrito ya existe para el usuario
    const cartDoc = await admin.firestore().collection("carts").doc(userId).get();
    if (cartDoc.exists) {
      // Agregar el producto al carrito existente
      const cart = cartDoc.data();
      const existingItem = cart.items.find((item) => item.productId === productId);

      if (existingItem) {
        // Si el producto ya está en el carrito, incrementar la cantidad
        existingItem.quantity += 1;
      } else {
        // Si el producto no está en el carrito, agregarlo
        cart.items.push({ productId, quantity: 1, ...product });
      }

      await admin.firestore().collection("carts").doc(userId).update(cart);
    } else {
      // Crear un nuevo carrito si no existe
      await admin.firestore().collection("carts").doc(userId).set({
        userId,
        items: [{ productId, quantity: 1, ...product }],
      });
    }

    res.json({ message: "Producto agregado al carrito.", cartId: userId });
  } catch (error) {
    console.error("Error al agregar producto al carrito:", error.message);
    res.status(500).json({ error: "Error al agregar producto al carrito." });
  }
});

// Ruta para eliminar un producto del carrito del cliente
app.post("/remove-from-cart", verifyRole(["client"]), async (req, res) => {
  const { userId, productId } = req.body;

  if (!userId || !productId) {
    return res.status(400).json({ error: "Falta userId o productId." });
  }

  try {
    // Obtener el carrito del cliente
    const cartDoc = await admin.firestore().collection("carts").doc(userId).get();
    if (!cartDoc.exists) {
      return res.status(404).json({ error: "Carrito no encontrado." });
    }

    const cart = cartDoc.data();
    const updatedItems = cart.items.filter((item) => item.productId !== productId);

    // Actualizar el carrito
    await admin.firestore().collection("carts").doc(userId).update({ items: updatedItems });

    res.json({ message: "Producto eliminado del carrito.", cartId: userId });
  } catch (error) {
    console.error("Error al eliminar producto del carrito:", error.message);
    res.status(500).json({ error: "Error al eliminar producto del carrito." });
  }
});

// Dashboards protegidos por rol
app.get("/admin-dashboard", verifyRole(["admin"]), (req, res) => {
  res.json({ message: "Bienvenido al dashboard de administrador." });
});
app.get("/kitchen-dashboard", verifyRole(["kitchen"]), (req, res) => {
  res.json({ message: "Bienvenido al dashboard de cocina." });
});
app.get("/waiter-dashboard", verifyRole(["waiter"]), (req, res) => {
  res.json({ message: "Bienvenido al dashboard de mesero." });
});
app.get("/client-dashboard", verifyRole(["client"]), (req, res) => {
  res.json({ message: "Bienvenido al dashboard de cliente." });
});

// Ruta de prueba
app.get("/", (req, res) => {
  res.send("Backend is running!");
});

// Manejador de errores global
app.use((err, req, res, next) => {
  console.error("Error global capturado:", err.message);
  res.status(500).json({ error: "Ocurrió un error inesperado en el servidor." });
});

// Iniciar el servidor
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});