# JWT-ADA

const express = require('express');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

// Secreto para firmar el token JWT
const secretKey = 'secreto';

// Middleware de autenticación
function authMiddleware(req, res, next) {
  // Verificar si se envió el token JWT en la cabecera de autorización
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'No se proporcionó un token de autorización' });
  }

  // Extraer el token JWT de la cabecera de autorización
  const token = authHeader.split(' ')[1];

  try {
    // Verificar y decodificar el token JWT
    const decodedToken = jwt.verify(token, secretKey);

    // Agregar el objeto decodificado del token JWT al objeto de solicitud
    req.user = decodedToken;

    // Continuar con la solicitud
    next();
  } catch (err) {
    // Enviar respuesta de error si el token es inválido
    return res.status(401).json({ message: 'Token de autorización inválido' });
  }
}

// Middleware de validación de roles
function roleMiddleware(rolesValidos) {
  return (req, res, next) => {
    // Verificar si el usuario tiene el rol requerido
    if (!rolesValidos.includes(req.user.role)) {
      return res.status(403).json({ message: 'Acceso denegado: se requiere un rol válido' });
    }

    // Continuar con la solicitud
    next();
  };
}

// Ruta protegida que requiere el rol "admin"
app.get('/admin', authMiddleware, roleMiddleware(['admin']), (req, res) => {
  res.json({ message: 'Acceso autorizado para el rol de administrador' });
});

// Ruta protegida que requiere el rol "usuario"
app.get('/usuario', authMiddleware, roleMiddleware(['usuario']), (req, res) => {
  res.json({ message: 'Acceso autorizado para el rol de usuario' });
});

// Ruta para iniciar sesión y generar el token JWT
app.post('/login', (req, res) => {
  // Verificar si el usuario existe en la base de datos y si la contraseña es correcta
  const username = req.body.username;
  const password = req.body.password;

  // Simulación de consulta a base de datos
  if (username === 'usuario' && password === 'secreto') {
    // Generar el token JWT con el rol "usuario"
    const token = jwt.sign({ username: username, role: 'usuario' }, secretKey);

    // Enviar el token JWT al cliente
    res.json({ token: token });
  } else if (username === 'admin' && password === 'secreto') {
    // Generar el token JWT con el rol "admin"
    const token = jwt.sign({ username: username, role: 'admin' }, secretKey);

    // Enviar el token JWT al cliente
    res.json({ token: token });
  } else {
    res.status(401).json({ message: 'Credenciales inválidas' });
  }
});

// Iniciar el servidor
app.listen(3000, () => {
  console.log('Servidor iniciado en http://localhost:3000');
});
