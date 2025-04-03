const admin = require('firebase-admin');
require('dotenv').config();

let serviceAcoountKey = JSON.parse(process.env.FIREBASE_CREDENTIALS);

// Inicialización solo una vez
if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAcoountKey),
  });
}

// Inicializa Firestore
const db = admin.firestore();

db.settings({ ignoreUndefinedProperties: true });

module.exports = db;