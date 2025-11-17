require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');

const db = require('./src/config/db');
const authRoutes = require('./src/modules/auth/auth.routes');

const app = express();

/* -------------------------------------------------
   1. Wait for DB before listening
   ------------------------------------------------- */
(async () => {
  try {
    await db.testConnection();               // <-- async!
  } catch (err) {
    console.error('DB connection failed – exiting');
    process.exit(1);
  }

  /* -------------------------------------------------
     2. Middleware (order matters)
     ------------------------------------------------- */
  app.use(helmet());
  app.use(cors());
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));
  app.use(morgan('dev'));

  /* -------------------------------------------------
     3. Health check
     ------------------------------------------------- */
  app.get('/health', (req, res) => {
    res.json({
      success: true,
      message: 'Server is running',
      timestamp: new Date().toISOString(),
    });
  });

  /* -------------------------------------------------
     4. API routes
     ------------------------------------------------- */
  app.use('/api/auth', authRoutes);

  /* -------------------------------------------------
     5. 404 – must be *after* all routes
     ------------------------------------------------- */
  app.use((req, res) => {
    res.status(404).json({
      success: false,
      message: 'Route not found',
    });
  });

  /* -------------------------------------------------
     6. Global error handler – **must have 4 args**
     ------------------------------------------------- */
  app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);

    res.status(err.status || 500).json({
      success: false,
      message: err.message || 'Internal server error',
      ...(process.env.NODE_ENV === 'development' && { stack: err.stack }),
    });
  });

  /* -------------------------------------------------
     7. Start server
     ------------------------------------------------- */
  const PORT = process.env.PORT || 5000;
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`Health check: http://localhost:${PORT}/health`);
  });
})();