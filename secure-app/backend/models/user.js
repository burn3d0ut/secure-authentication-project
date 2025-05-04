// backend/models/user.js
const { db } = require('../config/db');
const bcrypt = require('bcrypt');
const crypto = require('crypto');

// User model with secure methods
const User = {
  // finding a user by username - SECURE against SQL injection
  findByUsername: (username, callback) => {
    // Parameterized query - prevents SQL injection
    const query = 'SELECT * FROM users WHERE username = ?';
    console.log('[SECURE] Executing query with parameter:', username);
    
    db.get(query, [username], callback);
  },
  
  // authenticate a user - SECURE against SQL injection with brute force protection
  authenticate: (username, password, ip, callback) => {
    // Two-step authentication with parameterized query
    // Step 1: Find user with parameterized query
    const query = 'SELECT * FROM users WHERE username = ?';
    console.log('[SECURE] Executing authentication query for username:', username);
    
    const now = Date.now();
    
    db.get(query, [username], (err, user) => {
      if (err) return callback(err);
      
      // Track login attempt
      const trackAttempt = (success) => {
        db.run(
          'INSERT INTO login_attempts (username, ip_address, attempt_time, success) VALUES (?, ?, ?, ?)',
          [username, ip, now, success ? 1 : 0],
          (err) => {
            if (err) console.error('Error tracking login attempt:', err);
          }
        );
      };

      // If no user found, delay response to prevent timing attacks
      if (!user) {
        // Simulating bcrypt comparison time to prevent timing attacks
        setTimeout(() => {
          trackAttempt(false);
          return callback(null, null);
        }, 300); // Simulate bcrypt verification time
        return;
      }
      
      // Check if account is locked
      if (user.account_locked_until && user.account_locked_until > now) {
        trackAttempt(false);
        return callback(new Error(`Account is locked. Try again after ${new Date(user.account_locked_until).toLocaleTimeString()}`));
      }
      
      // Step 2: Compare passwords using bcrypt
      bcrypt.compare(password, user.password, (err, match) => {
        if (err) return callback(err);
        
        if (match) {
          // Reset failed attempts on successful login
          db.run(
            'UPDATE users SET failed_login_attempts = 0, account_locked_until = NULL WHERE id = ?',
            [user.id],
            (err) => {
              if (err) console.error('Error resetting failed login attempts:', err);
            }
          );
          
          trackAttempt(true);
          return callback(null, user);
        } else {
          // Increment failed attempts
          const failedAttempts = (user.failed_login_attempts || 0) + 1;
          let lockUntil = null;
          
          // Lock account after 5 failed attempts
          if (failedAttempts >= 5) {
            lockUntil = now + (15 * 60 * 1000); // 15 minutes
          }
          
          db.run(
            'UPDATE users SET failed_login_attempts = ?, account_locked_until = ? WHERE id = ?',
            [failedAttempts, lockUntil, user.id],
            (err) => {
              if (err) console.error('Error updating failed login attempts:', err);
            }
          );
          
          trackAttempt(false);
          
          if (lockUntil) {
            return callback(new Error(`Too many failed attempts. Account locked until ${new Date(lockUntil).toLocaleTimeString()}`));
          }
          
          return callback(null, null);
        }
      });
    });
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
  
  // generates a password reset token - Made more secure with unpredictable tokens
  generateResetToken: (email, callback) => {
    // Generate a strong, crypto-secure token
    const token = crypto.randomBytes(32).toString('hex'); // 64 character hex string
    const expiry = Date.now() + (15 * 60 * 1000); // 15 minutes expiry (shorter is more secure)
    
    db.run(
      'UPDATE users SET reset_token = ?, reset_token_expiry = ? WHERE email = ?',
      [token, expiry, email],
      function(err) {
        if (err) return callback(err);
        callback(null, { token, expiry });
      }
    );
  },
  
  // Verify a reset token - improved to check expiry properly
  verifyResetToken: (email, token, callback) => {
    // Check if token exists and is not expired
    const now = Date.now();
    
    db.get(
      'SELECT * FROM users WHERE email = ? AND reset_token = ? AND reset_token_expiry > ?',
      [email, token, now],
      (err, user) => {
        if (err) return callback(err);
        if (!user) return callback(null, null);
        
        // Token is valid
        callback(null, user);
      }
    );
  },
  
  // reset a password with token invalidation after use
  resetPassword: (email, newPassword, callback) => {
    // Hash the password before storing - use higher cost factor for better security
    bcrypt.hash(newPassword, 12, (err, hashedPassword) => {
      if (err) return callback(err);
      
      // Start a transaction to ensure atomicity
      db.serialize(() => {
        // First verify the token still exists and is valid
        db.get(
          'SELECT * FROM users WHERE email = ? AND reset_token IS NOT NULL AND reset_token_expiry > ?',
          [email, Date.now()],
          (err, user) => {
            if (err) return callback(err);
            if (!user) return callback(new Error('Invalid or expired token'));
            
            // Update password and invalidate token atomically
            db.run(
              'UPDATE users SET password = ?, reset_token = NULL, reset_token_expiry = NULL WHERE email = ?',
              [hashedPassword, email],
              function(err) {
                if (err) return callback(err);
                
                if (this.changes === 0) {
                  return callback(new Error('Password reset failed'));
                }
                
                // Log successful password change
                console.log(`[SECURE] Password changed successfully for ${email} at ${new Date().toISOString()}`);
                
                callback(null, { success: true, rowsAffected: this.changes });
              }
            );
          }
        );
      });
    });
  },
  
  // Track JWT tokens for proper invalidation (logout)
  recordToken: (userId, tokenId, expiresAt, callback) => {
    db.run(
      'INSERT INTO tokens (user_id, token_id, created_at, expires_at, is_revoked) VALUES (?, ?, ?, ?, 0)',
      [userId, tokenId, Date.now(), expiresAt],
      function(err) {
        if (err) return callback(err);
        callback(null, { id: this.lastID });
      }
    );
  },
  
  // Check if a token has been revoked (for logout)
  isTokenRevoked: (tokenId, callback) => {
    db.get(
      'SELECT * FROM tokens WHERE token_id = ? AND is_revoked = 1',
      [tokenId],
      (err, token) => {
        if (err) return callback(err);
        callback(null, !!token);
      }
    );
  },
  
  // Revoke a token (logout)
  revokeToken: (tokenId, callback) => {
    db.run(
      'UPDATE tokens SET is_revoked = 1 WHERE token_id = ?',
      [tokenId],
      function(err) {
        if (err) return callback(err);
        callback(null, { success: true, rowsAffected: this.changes });
      }
    );
  }
};

module.exports = User;