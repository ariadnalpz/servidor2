const express = require('express');
const cors = require('cors');
const authRoutes = require('./routes/auth');
require('dotenv').config();

const app = express();

// Configura CORS para permitir solicitudes desde el dominio de tu frontend
app.use(cors({
  origin: ['http://localhost:3000', 'https://frontend-teal-six-25.vercel.app'],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'], // Incluye OPTIONS explícitamente
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true, // Si planeas usar cookies o credenciales en el futuro
}));

// Maneja las solicitudes preflight (OPTIONS) manualmente
app.options('*', cors());

app.use(express.json());
app.use('/api', authRoutes);

const PORT = process.env.PORT || 3002;
app.listen(PORT, () => console.log(`Servidor 2 corriendo en puerto ${PORT}`));