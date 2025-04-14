const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const speakeasy = require('speakeasy');
const db = require('../config/firebase');
require('dotenv').config();

const router = express.Router();

// API getInfo (GET) - Sin rateLimit
router.get('/getInfo', async (req, res) => {
  try {
    const email = req.query.email; // Obtener el email desde la query (por ejemplo: /getInfo?email=server2@gmail.com)

    let userData = null;
    if (email) {
      const userSnapshot = await db.collection('users').where('email', '==', email).get();
      if (!userSnapshot.empty) {
        const user = userSnapshot.docs[0].data();
        userData = {
          username: user.username,
          grado: user.grado,
          grupo: user.grupo,
        };
      }
    }

    res.json({
      nodeVersion: process.version,
      student: {
        name: 'Ariadna Vanessa López Gómez',
        group: 'IDGS11',
      },
      user: userData, // Puede ser null si no se proporciona email o no se encuentra el usuario
    });
  } catch (error) {
    console.error('Error en getInfo:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// API Register (POST)
router.post('/register', async (req, res) => {
  const { email, username, password, grado, grupo } = req.body;

  if (!email || !username || !password || !grado || !grupo || !/\S+@\S+\.\S+/.test(email)) {
    return res.status(400).json({ error: 'Datos inválidos' });
  }

  try {
    const userSnapshot = await db.collection('users').where('email', '==', email).get();
    if (!userSnapshot.empty) {
      return res.status(400).json({ error: 'El usuario ya existe' });
    }

    const secret = speakeasy.generateSecret({
      name: `AriadnaApp:${email}`,
    });

    const hashedPassword = await bcrypt.hash(password, 10);

    await db.collection('users').add({
      email,
      username,
      password: hashedPassword,
      grado,
      grupo,
      otpSecret: secret.base32,
    });

    res.status(201).json({
      message: 'Usuario registrado',
      secret: secret.base32,
      otpauthUrl: secret.otpauth_url,
    });
  } catch (error) {
    console.error('Error en register:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// API Login (POST)
router.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const userSnapshot = await db.collection('users').where('email', '==', email).get();
    if (userSnapshot.empty) {
      return res.status(401).json({ error: 'Credenciales inválidas' });
    }

    const user = userSnapshot.docs[0].data();
    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) {
      return res.status(401).json({ error: 'Credenciales inválidas' });
    }

    res.json({ message: 'Ingresa el código OTP de Google Authenticator' });
  } catch (error) {
    console.error('Error en login:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// Verificar OTP y generar JWT
router.post('/verify-otp', async (req, res) => {
  const { email, otp } = req.body;

  try {
    const userSnapshot = await db.collection('users').where('email', '==', email).get();
    if (userSnapshot.empty) {
      return res.status(401).json({ error: 'Usuario no encontrado' });
    }

    const user = userSnapshot.docs[0].data();
    const secret = user.otpSecret;

    const verified = speakeasy.totp.verify({
      secret: secret,
      encoding: 'base32',
      token: otp,
      window: 1,
    });

    if (!verified) {
      return res.status(401).json({ error: 'Código OTP inválido' });
    }

    const token = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } catch (error) {
    console.error('Error en verify-otp:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// Ruta para iniciar la recuperación de contraseña (POST)
router.post('/recover-password', async (req, res) => {
  const { email } = req.body;

  if (!email || !/\S+@\S+\.\S+/.test(email)) {
    return res.status(400).json({ error: 'Correo inválido' });
  }

  try {
    const userSnapshot = await db.collection('users').where('email', '==', email).get();
    if (userSnapshot.empty) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    res.json({ message: 'Ingresa el código OTP de Google Authenticator para continuar' });
  } catch (error) {
    console.error('Error en recover-password:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// Ruta para restablecer la contraseña (POST)
router.post('/reset-password', async (req, res) => {
  const { email, otp, newPassword } = req.body;

  if (!email || !otp || !newPassword) {
    return res.status(400).json({ error: 'Datos incompletos' });
  }

  try {
    const userSnapshot = await db.collection('users').where('email', '==', email).get();
    if (userSnapshot.empty) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    const userDoc = userSnapshot.docs[0];
    const user = userDoc.data();
    const secret = user.otpSecret;

    const verified = speakeasy.totp.verify({
      secret: secret,
      encoding: 'base32',
      token: otp,
      window: 1,
    });

    if (!verified) {
      return res.status(401).json({ error: 'Código OTP inválido' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await db.collection('users').doc(userDoc.id).update({
      password: hashedPassword,
    });

    res.json({ message: 'Contraseña restablecida con éxito' });
  } catch (error) {
    console.error('Error en reset-password:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// Ruta para obtener logs (GET)
router.get('/logs', async (req, res) => {
  try {
    const logsSnapshot = await db.collection('logs').get();

    const server1Logs = { info: 0, error: 0 };
    const server2Logs = { info: 0, error: 0 };

    logsSnapshot.forEach(doc => {
      const { server, level } = doc.data();
      if (server === 'Servidor 1') server1Logs[level]++;
      else if (server === 'Servidor 2') server2Logs[level]++;
    });

    res.json({ server1: server1Logs, server2: server2Logs });
  } catch (error) {
    console.error('Error al obtener logs:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

module.exports = router;