# Secure Authentication Implementation Project

This project demonstrates common authentication security vulnerabilities and their secure implementations in web applications. It consists of two parallel applications: a vulnerable authentication system and its secure counterpart, allowing for side-by-side comparison of security practices.

## Project Overview

The project addresses the OWASP Top 10 security vulnerabilities related to authentication, including:

- SQL Injection
- Insecure credential storage
- User enumeration
- Brute force vulnerabilities
- Weak password reset mechanisms
- Parameter tampering
- Insecure session management

## Project Structure

```
.
├── EXPLOITING.md - Guide on exploiting the vulnerable app
├── SECURE_IMPLEMENTATION.md - Documentation of security improvements
├── vulnerable-app/ - Deliberately insecure authentication implementation
└── secure-app/ - Properly secured authentication implementation
```

## Setup and Installation

### Prerequisites

- Node.js (v14+)
- npm

### Running the Vulnerable App

```bash
# Navigate to the vulnerable app directory
cd vulnerable-app

# Install dependencies
npm install

# Start the application
npm start
```

The vulnerable application will be available at `http://localhost:3000`.

### Running the Secure App

```bash
# Navigate to the secure app directory
cd secure-app

# Install dependencies
npm install

# Start the application
npm start
```

The secure application will be available at `http://localhost:3000` (ensure the vulnerable app is not running simultaneously, or change the port).

## Demonstration Accounts

Both applications come pre-configured with the following accounts:

- Username: `admin`, Password: `chocolate` (Admin privileges)
- Username: `john`, Password: `987654321` (Standard user)
- Username: `edward`, Password: `spongebob` (Standard user)
- Username: `12345`, Password: `666666` (Standard user)

## Security Features Comparison

| Feature | Vulnerable App | Secure App |
|---------|---------------|------------|
| SQL Queries | String concatenation | Parameterized queries |
| Password Storage | Plain text | Bcrypt with salt |
| Error Messages | Username/password specific | Generic messages |
| Brute Force Protection | None | Rate limiting & account lockout |
| Reset Tokens | 4-digit numeric | Cryptographically secure (32 bytes) |
| Session Management | localStorage | JWT tokens with server validation |
| Authorization | Client-side parameter | Server-side JWT verification |
| Security Headers | None | CSP, X-Frame-Options, etc. |

## Educational Usage

This project is designed for educational purposes to:

1. Demonstrate how common authentication vulnerabilities can be exploited
2. Show best practices for implementing secure authentication
3. Provide a hands-on environment for security testing

## Exploiting the Vulnerable App

See the `EXPLOITING.md` document for a detailed walkthrough of vulnerability exploitation techniques, including:

- SQL injection for authentication bypass
- User enumeration via error messages
- Brute force attacks against login and password reset
- Parameter tampering for privilege escalation

## Security Implementation Details

See the `SECURE_IMPLEMENTATION.md` document for in-depth explanations of the security improvements, including code examples and rationale.

## Warning

The vulnerable app contains intentional security flaws and should never be deployed in a production environment or exposed to the public internet.
