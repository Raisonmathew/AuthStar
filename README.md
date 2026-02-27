# IDaaS Platform - Identity as a Service

A production-grade Identity-as-a-Service platform built with Rust and React, featuring enterprise authentication, B2B organization management, and Stripe billing integration.

## 🚀 Features

- **Authentication**: Email/password, OAuth (Google, GitHub, Microsoft), passwordless (magic links, OTP)
- **Multi-Factor Authentication**: TOTP, SMS, backup codes
- **B2B Organizations**: Multi-tenant workspace management with RBAC
- **Billing**: Stripe integration with subscription management
- **Session Management**: Secure JWT-based sessions with automatic refresh
- **Developer SDKs**: JavaScript/TypeScript, Python, Go
- **Hosted UI**: Pre-built authentication pages

## 📁 Project Structure

```
idaas-platform/
├── backend/          # Rust backend services
├── frontend/         # React hosted authentication pages
├── sdks/            # Client SDKs
├── infrastructure/  # Terraform, Kubernetes configs
├── docs/            # Documentation
└── scripts/         # Utility scripts
```

## 🛠️ Tech Stack

**Backend:**
- Rust with Axum framework
- PostgreSQL 16 for data persistence
- Redis 7 for caching and sessions
- Stripe for billing

**Frontend:**
- React 18 with TypeScript
- Vite for build tooling
- Tailwind CSS + shadcn/ui
- XState for authentication flows

## 🏃 Quick Start

### Prerequisites

- Rust 1.75+
- Node.js 20+
- PostgreSQL 16
- Redis 7
- Docker & Docker Compose

### Development Setup

1. **Clone and setup environment:**
```bash
cd idaas-platform
cp backend/.env.example backend/.env
cp frontend/.env.example frontend/.env
```

2. **Start infrastructure:**
```bash
docker-compose -f infrastructure/docker-compose/docker-compose.dev.yml up -d
```

3. **Run database migrations:**
```bash
cd backend
cargo install sqlx-cli --no-default-features --features postgres
sqlx migrate run
```

4. **Start backend:**
```bash
cd backend
cargo run --bin api_server
```

5. **Start frontend:**
```bash
cd frontend
npm install
npm run dev
```

The API will be available at `http://localhost:3000` and the frontend at `http://localhost:5173`.

## 📚 Documentation

- [Technical Overview](docs/TECHNICAL_OVERVIEW.md) - How everything works under the hood
- [Architecture Overview](docs/ARCHITECTURE.md) - System design, installation, API reference
- [Integration Guide](docs/INTEGRATION_GUIDE.md) - Adding IDaaS to your React app
- [EIAA Compliance](docs/EIAA_COMPLIANCE.md) - Entitlement-Independent Architecture analysis

## 🧪 Testing

```bash
# Backend tests
cd backend
cargo test --all-features

# Frontend tests
cd frontend
npm test
```

## 📄 License

MIT License - see LICENSE file for details

## 🤝 Contributing

See [CONTRIBUTING.md](docs/CONTRIBUTING.md) for contribution guidelines.
