// backend/config/db.js
const sqlite3 = require('sqlite3').verbose();

//create an in-memory database (vulnerable - data disappears when server restarts)
const db = new sqlite3.Database(':memory:');

// Initialize database with users table
const initializeDatabase = () => {
  return new Promise((resolve, reject) => {
    db.serialize(() => {
      // creates users table with weak password storage (plaintext)
      db.run(`
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username TEXT UNIQUE,
          password TEXT, 
          email TEXT,
          reset_token TEXT,
          reset_token_expiry INTEGER,
          is_admin BOOLEAN
        )
      `, (err) => {
        if (err) {
          console.error('Error creating users table:', err);
          reject(err);
          return;
        }

        // Check if users already exist
        db.get('SELECT COUNT(*) as count FROM users', (err, row) => {
          if (err) {
            console.error('Error checking users:', err);
            reject(err);
            return;
          }

          // this "if" confition only inserts demo users if table is empty
          if (row.count === 0) {
            // Insert some demo users with plaintext passwords (vulnerability #1)
            const users = [
              { username: 'admin', password: 'chocolate', email: 'admin@example.com', is_admin: true },
              { username: 'john', password: '987654321', email: 'john@example.com', is_admin: false },
              { username: 'edward', password: 'spongebob', email: 'alice@example.com', is_admin: false },
              { username: '12345', password: '666666', email: 'bob@example.com', is_admin: false },
            ];

            const stmt = db.prepare('INSERT INTO users (username, password, email, is_admin) VALUES (?, ?, ?, ?)');
            users.forEach(user => {
              stmt.run(user.username, user.password, user.email, user.is_admin);
            });
            stmt.finalize(() => {
              console.log('Demo users created successfully');
              resolve();
            });
          } else {
            console.log('Users table already contains data');
            resolve();
          }
        });
      });
    });
  });
};

module.exports = {
  db,
  initializeDatabase
};