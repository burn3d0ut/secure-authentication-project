// server.js - Main server file with secure auth implementation
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const helmet = require('helmet');
const path = require('path');
const { db, initializeDatabase } = require('./config/db');
const authRoutes = require('./routes/auth');

// Setup Express app
const app = express();
const PORT = 3000;

// Security middleware
app.use(helmet()); // Adds various HTTP headers for security

// Configure CORS properly
const corsOptions = {
  origin: 'http://localhost:3000', // In production, restrict to your domain
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization']
};
app.use(cors(corsOptions));

// Body parser with limits to prevent DOS attacks
app.use(bodyParser.json({ limit: '100kb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '100kb' }));

// Static file serving for frontend
app.use(express.static(path.join(__dirname, '../frontend')));

// Add security middleware for all routes
app.use((req, res, next) => {
  // Log requests (in production, use a proper logging library)
  console.log(`${new Date().toISOString()} - ${req.method} ${req.originalUrl} - ${req.ip}`);
  
  // Set additional security headers
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Content-Security-Policy', "default-src 'self'");
  
  next();
});

// Auth routes for API endpoints
app.use('/api', authRoutes);

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Server error:', err.stack);
  
  // Don't expose error details in production
  const isDevelopment = process.env.NODE_ENV !== 'production';
  const message = isDevelopment ? err.message : 'Server error occurred';
  
  res.status(500).json({ error: message });
});

// Server startup
const startServer = async () => {
  try {
    // Create database and seed with test users
    await initializeDatabase();
    
    app.listen(PORT, () => {
      console.log(`Secure auth server running at http://localhost:${PORT}`);
      console.log(`Access the application at http://localhost:${PORT}`);
    });
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
};

startServer();

module.exports = app;