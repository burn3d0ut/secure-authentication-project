// backend/routes/auth.js
const express = require('express');
const User = require('../models/user');
const router = express.Router();

// login route - vulnerable to brute force
router.post('/login', (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }
  
  // Vulnerable: using direct model method with SQL injection
  User.authenticate(username, password, (err, user) => {
    if (err) {
      console.error('Login error:', err);
      return res.status(500).json({ error: 'Database error' });
    }
    
    if (user) {
      // Vulnerable: No proper session management, just sending user info
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
      // Vulnerable: Different error message based on whether username exists
      // This enables user enumeration attacks
      User.findByUsername(username, (err, existingUser) => {
        if (err) {
          return res.status(500).json({ error: 'Database error' });
        }
        
        if (existingUser) {
          return res.status(401).json({ error: 'Incorrect password' });
        } else {
          return res.status(401).json({ error: 'User not found' });
        }
      });
    }
  });
});

// checks username route - vulnerable to user enumeration
router.post('/check-username', (req, res) => {
  const { username } = req.body;
  
  if (!username) {
    return res.status(400).json({ error: 'Username is required' });
  }
  
  User.checkUsernameExists(username, (err, exists) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    
    // Vulnerable: Explicitly tells if username exists
    res.json({ exists, message: exists ? 'Username exists' : 'Username does not exist' });
  });
});

// Password reset request route - vulnerable to token prediction
router.post('/reset-password-request', (req, res) => {
  const { email } = req.body;
  
  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }
  
  User.findByEmail(email, (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    
    if (!user) {
      // Vulnerable: Tells if email exists
      return res.status(404).json({ error: 'Email not found' });
    }
    
    User.generateResetToken(email, (err, result) => {
      if (err) {
        return res.status(500).json({ error: 'Failed to generate reset token' });
      }
      
      // vulnerable: Exposes the token in the response
      console.log(`Password reset token for ${email}: ${result.token}`);
      res.json({ 
        success: true, 
        message: 'Password reset token generated',
        token: result.token
      });
    });
  });
});

// Add this new route to your auth.js file
// Place it after the reset-password-request route and before the reset-password route

// Verify reset token endpoint
router.post('/verify-reset-token', (req, res) => {
  const { email, token } = req.body;
  
  if (!email || !token) {
    return res.status(400).json({ 
      success: false,
      error: 'Email and token are required',
      message: 'Email and token are required'
    });
  }
  
  // Verify the token using the same user model method
  User.verifyResetToken(email, token, (err, user) => {
    if (err) {
      return res.status(500).json({ 
        success: false,
        error: 'Database error',
        message: 'Database error'
      });
    }
    
    if (!user) {
      return res.status(400).json({ 
        success: false,
        error: 'Invalid token or email',
        message: 'Invalid token or email'
      });
    }
    
    // Token is valid
    res.json({ 
      success: true, 
      message: 'Token verified successfully'
    });
  });
});


// reset password route - vulnerable to token brute force
router.post('/reset-password', (req, res) => {
  const { email, token, newPassword } = req.body;
  
  if (!email || !token || !newPassword) {
    return res.status(400).json({ error: 'Email, token, and new password are required' });
  }
  
  // Vulnerable: No CSRF protection
  User.verifyResetToken(email, token, (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    
    if (!user) {
      return res.status(400).json({ error: 'Invalid token or email' });
    }
    
    // Vulnerable: Not checking if token is expired
    // const now = Date.now();
    // if (user.reset_token_expiry < now) {
    //   return res.status(400).json({ error: 'Token has expired' });
    // }
    
    User.resetPassword(email, newPassword, (err, result) => {
      if (err) {
        return res.status(500).json({ error: 'Failed to reset password' });
      }
      
      res.json({ success: true, message: 'Password updated successfully' });
    });
  });
});

// Admin route - vulnerable to parameter tampering
router.get('/admin/users', (req, res) => {
  // Vulnerable: Relies on client-side parameter for authorization
  const isAdmin = req.query.isAdmin === 'true' || req.query.admin === 'true';
  
  if (!isAdmin) {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  
  User.getAllUsers((err, users) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    
    res.json({ users });
  });
});

module.exports = router;