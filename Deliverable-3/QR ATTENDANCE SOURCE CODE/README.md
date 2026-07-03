# Secure QR-Based Attendance Management System

A production-grade attendance system using dynamically-refreshing QR codes to prevent proxy attendance and replay attacks. Built with a unified Express.js backend and modern glassmorphism frontend, optimized for Vercel deployment.

## 🏗️ Unified Architecture

The project has been consolidated into a single, high-performance Node.js application:

- **Backend (`api/index.js`)**: A unified Express server handling Authentication, QR Generation (HMAC-SHA256), Session Management, and Role-Based Access Control (RBAC).
- **Frontend (`public/`)**: Three specialized portals (Student, Teacher, Admin) built with responsive, premium UI.
- **Database (`lib/db.js`)**: Turso (libSQL) integration for globally distributed edge data.

## 🔒 Security Features

| Feature | Implementation |
|---------|---------------|
| **Dynamic QR Codes** | Refreshes every 15s with high-entropy nonces. |
| **Replay Prevention** | Single-use nonces + strict timestamp validation window. |
| **QR Integrity** | HMAC-SHA256 signed payloads preventing data tampering. |
| **Device Binding** | Hardware-linked fingerprinting on first scan. |
| **Authentication** | JWT-based sessions with bcrypt password hashing. |
| **Rate Limiting** | DDoS and brute-force protection on all auth endpoints. |
| **Security Headers** | Custom CSP, HSTS, and X-Frame-Options configured. |

## 📁 Project Structure

```
├── api/                # Consolidated Backend (Express.js)
├── lib/                # Shared logic & Database connection
├── public/             # Frontend Portals (Admin, Student, Teacher)
├── docs/               # Security Documentation & Reports
├── database/           # Schema references
├── vercel.json         # Deployment configuration
└── package.json        # Unified dependencies
```

## 🚀 Getting Started

### 1. Environment Setup
Copy `.env.example` to `.env` and configure your Turso Database URL and Secrets.

### 2. Local Development
```bash
npm install
npm run dev
```

### 3. Deployment
The project is configured for one-click deployment to **Vercel**. Use the `set-env.js` script to sync your environment variables.

## 📄 Documentation
Detailed security analysis can be found in:
- [Threat Model](docs/threat-model.md)
- [SSDLC Report](docs/ssdlc-report.md)
- [Security Scan (OWASP ZAP)](docs/zap-report.html)
