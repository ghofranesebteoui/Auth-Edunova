// backend/config/db.js
require('dotenv').config();
const mysql = require('mysql2/promise');

const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'edunova',
  port: process.env.DB_PORT || 3306,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  enableKeepAlive: true,
  keepAliveInitialDelay: 0
});

// Test database connection on startup
const testConnection = async () => {
  try {
    const connection = await pool.getConnection();
    console.log('✅ Base de données edunova connectée (pool)');
    connection.release();
  } catch (err) {
    console.error('❌ Erreur de connexion à la base de données:', err.message);
    console.error('Vérifiez vos paramètres de base de données dans .env');
    // Don't exit process - let app handle it gracefully
  }
};

// Run connection test

module.exports = { pool, testConnection };