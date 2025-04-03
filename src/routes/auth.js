const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const speakeasy = require('speakeasy');
const { saveLog } = require('../models/log');
const db = require('../config/firebase');
require('dotenv').config();

const router = express.Router();

// Middleware para registrar logs detallados (Servidor 2)
const logMiddleware = async (req, res, next) => {
  const startTime = Date.now();
  const originalSend = res.send;
  
  res.send = function (body) {
    const responseTime = Date.now() - startTime;
    const logLevel = res.statusCode >= 400 ? 'error' : 'info';
    
    const logDetails = {
      method: req.method,
      url: req.url,
      status: res.statusCode,
      responseTime,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      requestBody: req.body,
      responseBody: typeof body === 'string' ? body : JSON.stringify(body)
    };

    // Modificamos saveLog para que use 'Servidor 2'
    saveLog(
      logLevel,
      `${req.method} ${req.url} completed`,
      { ...logDetails, server: 'Servidor 2' } // Sobreescribimos el server
    ).catch(error => {
      console.error('Error en middleware al guardar log en Servidor 2:', error);
    });

    return originalSend.apply(res, arguments);
  };
  
  next();
};

// Aplicar middleware a todas las rutas
router.use(logMiddleware);

// API getInfo (GET) - Sin limiter
router.get('/getInfo', async (req, res) => {
  try {
    res.json({
      nodeVersion: process.version,
      student: {
        name: 'Ariadna Vanessa López Gómez',
        group: 'IDGS11',
      },
    });
  } catch (error) {
    console.error('Error en getInfo (Servidor 2):', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// API Register (POST) - Sin limiter
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
    console.error('Error en register (Servidor 2):', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// API Login (POST) - Sin limiter
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
    console.error('Error en login (Servidor 2):', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// Verificar OTP y generar JWT - Sin limiter
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
    console.error('Error en verify-otp (Servidor 2):', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// Nueva ruta para obtener logs (GET) - Sin limiter
router.get('/logs', async (req, res) => {
  try {
    const logsSnapshot = await db.collection('logs')
      .orderBy('timestamp', 'desc')
      .limit(100)
      .get();
    
    const logs = logsSnapshot.docs.map(doc => doc.data());
    
    const summary = {
      server1: { info: 0, error: 0 },
      server2: { info: 0, error: 0 }
    };

    logs.forEach(log => {
      if (log.server === 'Servidor 1') {
        summary.server1[log.level]++;
      } else if (log.server === 'Servidor 2') {
        summary.server2[log.level]++;
      }
    });

    res.json({ 
      summary,
      recentLogs: logs
    });
  } catch (error) {
    console.error('Error al obtener logs (Servidor 2):', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

module.exports = router;