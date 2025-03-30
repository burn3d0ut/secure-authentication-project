// server.js - Main server file with vulnerable auth implementation
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');
const { db, initializeDatabase } = require('./config/db');
const authRoutes = require('./routes/auth');

// Setup Express app
const app = express();
const PORT = 3000;

// Middleware configuration
app.use(cors()); // CORS enabled with no restrictions - security vulnerability
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Static file serving for frontend
app.use(express.static(path.join(__dirname, '../frontend')));

// Auth routes for API endpoints
app.use('/api', authRoutes);

// Backup routes for demo purposes
// These demonstrate the vulnerabilities more clearly

// Direct login endpoint with SQL injection vulnerability
app.post('/api/direct-login', (req, res) => {
  const { username, password } = req.body;
  
  // Vulnerable to SQL injection - no parameter sanitization
  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
  
  // Query logging for debugging
  console.log('Direct login query:', query);
  
  db.get(query, (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    
    if (user) {
      res.json({ 
        success: true, 
        message: 'Login successful',
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          isAdmin: user.is_admin
        }
      });
    } else {
      if (username) {
        // Different error messages allow username enumeration
        const checkUserQuery = `SELECT * FROM users WHERE username = '${username}'`;
        db.get(checkUserQuery, (err, existingUser) => {
          if (existingUser) {
            return res.status(401).json({ error: 'Incorrect password' });
          } else {
            return res.status(401).json({ error: 'User not found' });
          }
        });
      } else {
        res.status(401).json({ error: 'Invalid credentials' });
      }
    }
  });
});

// Server startup
const startServer = async () => {
  try {
    // Create database and seed with test users
    await initializeDatabase();
    
    app.listen(PORT, () => {
      console.log(`Vulnerable auth server running at http://localhost:${PORT}`);
      console.log(`Access the application at http://localhost:${PORT}`);
    });
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
};

startServer();

module.exports = app;