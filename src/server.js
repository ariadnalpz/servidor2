const express = require('express');
const cors = require('cors'); // Importa el paquete cors
const authRoutes = require('./routes/auth');
require('dotenv').config();

const app = express();

// Configura CORS para permitir solicitudes
app.use(cors());

app.use(express.json());
app.use('/api', authRoutes);

const PORT = process.env.PORT || 3002;
app.listen(PORT, () => console.log(`Servidor 2 corriendo en puerto ${PORT}`));