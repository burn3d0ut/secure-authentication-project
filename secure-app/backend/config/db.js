// backend/config/db.js
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const path = require('path');
const fs = require('fs');

// Create a data directory if it doesn't exist
const dbDir = path.join(__dirname, '../data');
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
}

// Use a file-based database instead of in-memory for persistence
const db = new sqlite3.Database(path.join(dbDir, 'secure-auth.db'));

// Initialize database with users table
const initializeDatabase = async () => {
  return new Promise((resolve, reject) => {
    db.serialize(() => {
      // Add additional fields for security
      db.run(`
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username TEXT UNIQUE,
          password TEXT, 
          email TEXT,
          reset_token TEXT,
          reset_token_expiry INTEGER,
          is_admin BOOLEAN,
          failed_login_attempts INTEGER DEFAULT 0,
          account_locked_until INTEGER
        )
      `, (err) => {
        if (err) {
          console.error('Error creating users table:', err);
          reject(err);
          return;
        }

        // Check if users already exist
        db.get('SELECT COUNT(*) as count FROM users', async (err, row) => {
          if (err) {
            console.error('Error checking users:', err);
            reject(err);
            return;
          }

          // this "if" condition only inserts demo users if table is empty
          if (row.count === 0) {
            try {
              // Hash passwords with bcrypt
              const saltRounds = 12;
              
              // Create demo users with hashed passwords
              const users = [
                { 
                  username: 'admin', 
                  // Hash passwords securely with bcrypt
                  password: await bcrypt.hash('chocolate', saltRounds), 
                  email: 'admin@example.com', 
                  is_admin: true 
                },
                { 
                  username: 'john', 
                  password: await bcrypt.hash('987654321', saltRounds), 
                  email: 'john@example.com', 
                  is_admin: false 
                },
                { 
                  username: 'edward', 
                  password: await bcrypt.hash('spongebob', saltRounds), 
                  email: 'alice@example.com', 
                  is_admin: false 
                },
                { 
                  username: '12345', 
                  password: await bcrypt.hash('666666', saltRounds), 
                  email: 'bob@example.com', 
                  is_admin: false 
                },
              ];

              // Use parameterized queries for safe inserts
              const stmt = db.prepare('INSERT INTO users (username, password, email, is_admin) VALUES (?, ?, ?, ?)');
              
              for (const user of users) {
                await new Promise((res, rej) => {
                  stmt.run(user.username, user.password, user.email, user.is_admin, (err) => {
                    if (err) rej(err);
                    else res();
                  });
                });
              }
              
              await new Promise((res, rej) => {
                stmt.finalize((err) => {
                  if (err) rej(err);
                  else res();
                });
              });
              
              console.log('Demo users created with securely hashed passwords');
              resolve();
            } catch (error) {
              console.error('Error creating demo users:', error);
              reject(error);
            }
          } else {
            console.log('Users table already contains data');
            resolve();
          }
        });
      });
      
      // Create table to track login attempts for brute force protection
      db.run(`
        CREATE TABLE IF NOT EXISTS login_attempts (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username TEXT,
          ip_address TEXT,
          attempt_time INTEGER,
          success BOOLEAN
        )
      `, (err) => {
        if (err) {
          console.error('Error creating login_attempts table:', err);
        }
      });
      
      // Create table to track and manage JWT tokens for secure session handling
      db.run(`
        CREATE TABLE IF NOT EXISTS tokens (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER,
          token_id TEXT UNIQUE,
          created_at INTEGER,
          expires_at INTEGER,
          is_revoked BOOLEAN DEFAULT 0,
          FOREIGN KEY (user_id) REFERENCES users(id)
        )
      `, (err) => {
        if (err) {
          console.error('Error creating tokens table:', err);
        }
      });
    });
  });
};

module.exports = {
  db,
  initializeDatabase
};