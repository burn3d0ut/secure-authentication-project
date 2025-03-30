// backend/models/user.js
const { db } = require('../config/db');

// User model with vulnerable implementations
const User = {
  // finding a user by username - vulnerable to SQL injection
  findByUsername: (username, callback) => {
    // Vulnerable SQL query - direct string interpolation
    const query = `SELECT * FROM users WHERE username = '${username}'`;
    console.log('[VULNERABLE] Executing query:', query);
    
    db.get(query, callback);
  },
  
  // authenticate a user - vulnerable to SQL injection
  authenticate: (username, password, callback) => {
    // Vulnerable SQL query - direct string interpolation
    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
    console.log('[VULNERABLE] Executing query:', query);
    
    db.get(query, callback);
  },
  
  // Get all users
  getAllUsers: (callback) => {
    db.all('SELECT id, username, email, is_admin FROM users', callback);
  },
  
  // Check if a username exists - for enumeration attacks
  checkUsernameExists: (username, callback) => {
    db.get('SELECT id FROM users WHERE username = ?', [username], (err, user) => {
      if (err) return callback(err);
      callback(null, !!user);
    });
  },
  
  // Finding a user by email
  findByEmail: (email, callback) => {
    db.get('SELECT * FROM users WHERE email = ?', [email], callback);
  },
  
  // generates a password reset token - vulnerable (predictable tokens)
  generateResetToken: (email, callback) => {
    // Generate a weak, predictable token
    const timestamp = Date.now();
    const token = (timestamp % 10000).toString().padStart(4, '0'); // Just a 4-digit number
    const expiry = timestamp + 3600000; // 1 hour expiry
    
    db.run(
      'UPDATE users SET reset_token = ?, reset_token_expiry = ? WHERE email = ?',
      [token, expiry, email],
      function(err) {
        if (err) return callback(err);
        callback(null, { token, expiry });
      }
    );
  },
  
  // Verify a reset token - vulnerable (doesn't check expiry properly)
  verifyResetToken: (email, token, callback) => {
    db.get(
      'SELECT * FROM users WHERE email = ? AND reset_token = ?',
      [email, token],
      callback
    );
  },
  
  // reset a password
  resetPassword: (email, newPassword, callback) => {
    db.run(
      'UPDATE users SET password = ?, reset_token = NULL, reset_token_expiry = NULL WHERE email = ?',
      [newPassword, email],
      function(err) {
        if (err) return callback(err);
        callback(null, { success: true, rowsAffected: this.changes });
      }
    );
  }
};

module.exports = User;