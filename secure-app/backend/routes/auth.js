// backend/routes/auth.js
const express = require('express');
const User = require('../models/user');
const router = express.Router();
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');

// JWT configuration
const JWT_SECRET = process.env.JWT_SECRET || 'your-secure-jwt-secret-key';
const JWT_EXPIRES_IN = '1h';

// Rate limiter for login attempts - prevents brute force attacks
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 requests per windowMs
  message: { error: 'Too many login attempts, please try again after 15 minutes' }
});

// login route - now protected against brute force
router.post('/login', loginLimiter, (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }
  
  // Get IP address for tracking
  const ipAddress = req.ip || req.connection.remoteAddress;
  
  // Secure: using model method with parameterized queries and brute force protection
  User.authenticate(username, password, ipAddress, (err, user) => {
    // Check for specific account lockout errors
    if (err) {
      console.error('Login error:', err);
      return res.status(429).json({ error: err.message });
    }
    
    if (user) {
      // Generate a unique token ID for tracking
      const tokenId = crypto.randomBytes(16).toString('hex');
      
      // Calculate token expiration
      const expiresInMs = JWT_EXPIRES_IN.endsWith('h') 
        ? parseInt(JWT_EXPIRES_IN) * 60 * 60 * 1000 
        : parseInt(JWT_EXPIRES_IN) * 60 * 1000;
      const expiresAt = Date.now() + expiresInMs;
      
      // Generate JWT token for secure session management
      const token = jwt.sign({ 
        jti: tokenId, // JWT ID for tracking/revocation
        id: user.id,
        username: user.username,
        email: user.email,
        isAdmin: user.is_admin
      }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
      
      // Record token for tracking and revocation
      User.recordToken(user.id, tokenId, expiresAt, (err, result) => {
        if (err) {
          console.error('Error recording token:', err);
          return res.status(500).json({ error: 'Server error' });
        }
        
        res.json({ 
          success: true, 
          message: 'Login successful',
          token
        });
      });
    } else {
      // SECURE: Generic error message - prevents user enumeration
      return res.status(401).json({ error: 'Invalid username or password' });
    }
  });
});

// checks username route - fixed to prevent user enumeration
router.post('/check-username', (req, res) => {
  // SECURE: Disabled or give generic response - prevents user enumeration
  res.json({ message: 'This endpoint has been disabled for security reasons' });
});

// Password reset request route - more secure with unpredictable tokens
router.post('/reset-password-request', (req, res) => {
  const { email } = req.body;
  
  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }
  
  User.findByEmail(email, (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Server error' });
    }
    
    // SECURE: Always return success whether user exists or not - prevents user enumeration
    if (!user) {
      // Simulate processing time for non-existing emails to prevent timing attacks
      setTimeout(() => {
        return res.json({ 
          success: true, 
          message: 'If your email exists in our system, you will receive a password reset link shortly.'
        });
      }, 1000);
      return;
    }
    
    User.generateResetToken(email, (err, result) => {
      if (err) {
        return res.status(500).json({ error: 'Server error' });
      }
      
      // In a real app, send an email with the token
      // For demo, just log it securely
      console.log(`[SECURE DEMO] Reset token for ${email}: ${result.token}`);
      
      // SECURE: Don't expose the token in the response
      res.json({ 
        success: true, 
        message: 'If your email exists in our system, you will receive a password reset link shortly.'
      });
    });
  });
});

// Verify reset token endpoint
router.post('/verify-reset-token', (req, res) => {
  const { email, token } = req.body;
  
  if (!email || !token) {
    return res.status(400).json({ 
      success: false,
      error: 'Email and token are required'
    });
  }
  
  // SECURE: Verifies token with parameterized query and checks expiry
  User.verifyResetToken(email, token, (err, user) => {
    if (err) {
      return res.status(500).json({ 
        success: false,
        error: 'Server error'
      });
    }
    
    if (!user) {
      return res.status(400).json({ 
        success: false,
        error: 'Invalid or expired token'
      });
    }
    
    // Token is valid
    res.json({ 
      success: true, 
      message: 'Token verified successfully'
    });
  });
});

// reset password route - now properly validates tokens
router.post('/reset-password', (req, res) => {
  const { email, token, newPassword } = req.body;
  
  if (!email || !token || !newPassword) {
    return res.status(400).json({ error: 'Email, token, and new password are required' });
  }
  
  // First verify the token is valid and not expired
  User.verifyResetToken(email, token, (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Server error' });
    }
    
    if (!user) {
      return res.status(400).json({ error: 'Invalid or expired token' });
    }
    
    // SECURE: Password is hashed by the model method
    User.resetPassword(email, newPassword, (err, result) => {
      if (err) {
        return res.status(500).json({ error: err.message || 'Server error' });
      }
      
      res.json({ success: true, message: 'Password updated successfully' });
    });
  });
});

// Middleware to verify JWT tokens for protected routes
const verifyToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN format
  
  if (!token) {
    return res.status(401).json({ error: 'Access denied. No token provided.' });
  }
  
  try {
    const verified = jwt.verify(token, JWT_SECRET);
    
    // Check if token has been revoked (for logout)
    User.isTokenRevoked(verified.jti, (err, isRevoked) => {
      if (err) {
        console.error('Error checking token revocation:', err);
        return res.status(500).json({ error: 'Server error' });
      }
      
      if (isRevoked) {
        return res.status(401).json({ error: 'Token has been revoked. Please log in again.' });
      }
      
      req.user = verified;
      req.tokenId = verified.jti;
      next();
    });
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Token has expired. Please log in again.' });
    }
    return res.status(401).json({ error: 'Invalid token' });
  }
};

// Add logout route for token revocation
router.post('/logout', verifyToken, (req, res) => {
  User.revokeToken(req.tokenId, (err, result) => {
    if (err) {
      console.error('Logout error:', err);
      return res.status(500).json({ error: 'Server error during logout' });
    }
    
    res.json({ success: true, message: 'Logged out successfully' });
  });
});

// Get current user info
router.get('/me', verifyToken, (req, res) => {
  User.findByUsername(req.user.username, (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Server error' });
    }
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json({
      id: user.id,
      username: user.username,
      email: user.email,
      isAdmin: user.is_admin
    });
  });
});

// Admin route - secure with proper authorization checks
router.get('/admin/users', verifyToken, (req, res) => {
  // SECURE: Check if user is admin from verified token
  if (!req.user.isAdmin) {
    return res.status(403).json({ error: 'Access denied: Admin privileges required' });
  }
  
  User.getAllUsers((err, users) => {
    if (err) {
      return res.status(500).json({ error: 'Server error' });
    }
    
    res.json({ users });
  });
});

module.exports = router;