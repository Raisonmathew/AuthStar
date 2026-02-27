#!/bin/bash

# IDaaS Development Environment Setup Script

set -e

echo "🚀 Setting up IDaaS development environment..."

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker and try again."
    exit 1
fi

echo "✅ Docker is running"

# Check if Rust is installed
if ! command -v cargo &> /dev/null; then
    echo "❌ Rust is not installed. Install from https://rustup.rs/"
    exit 1
fi

echo "✅ Rust is installed: $(rustc --version)"

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo "❌ Node.js is not installed. Install from https://nodejs.org/"
    exit 1
fi

echo "✅ Node.js is installed: $(node --version)"

# Start Docker services
echo "📦 Starting Docker services..."
cd infrastructure/docker-compose
docker-compose -f docker-compose.dev.yml up -d
cd ../..

echo "⏳ Waiting for services to be healthy..."

max_retries=30
retry_count=0
healthy=false

while [ $retry_count -lt $max_retries ]; do
    if docker exec idaas-postgres-dev pg_isready -U idaas_user -d idaas > /dev/null 2>&1; then
        healthy=true
        break
    fi
    
    echo -n "."
    sleep 1
    retry_count=$((retry_count+1))
done

echo "" # New line

if [ "$healthy" = false ]; then
    echo "❌ Database failed to start within timeout."
    exit 1
fi

echo "✅ Database is ready"

# Install sqlx-cli if not present
if ! command -v sqlx &> /dev/null; then
    echo "📥 Installing sqlx-cli..."
    cargo install sqlx-cli --no-default-features --features postgres
fi

echo "✅ sqlx-cli is installed"

# Copy environment file if not exists
if [ ! -f backend/.env ]; then
    echo "📝 Creating backend/.env from template..."
    cp backend/.env.example backend/.env
    echo "⚠️  Please edit backend/.env with your configuration"
fi

# Run database migrations
echo "🗄️  Running database migrations..."
cd backend
export DATABASE_URL="postgres://idaas_user:dev_password_change_me@localhost:5432/idaas"
sqlx migrate run --source crates/db_migrations/migrations
cd ..

echo "✅ Database migrations completed"

# Generate JWT keys for development
echo "🔐 Generating development JWT keys..."
mkdir -p backend/.keys

if [ ! -f backend/.keys/private.pem ]; then
    openssl ecparam -genkey -name prime256v1 -noout -out backend/.keys/private.pem
    openssl ec -in backend/.keys/private.pem -pubout -out backend/.keys/public.pem
    echo "✅ JWT keys generated in backend/.keys/"
    echo "⚠️  Add these to your backend/.env file"
fi

# Install frontend dependencies
if [ -d "frontend" ]; then
    echo "📦 Installing frontend dependencies..."
    cd frontend
    if [ ! -f .env ]; then
        cp .env.example .env 2>/dev/null || echo "VITE_API_URL=http://localhost:3000" > .env
    fi
    npm install
    cd ..
    echo "✅ Frontend dependencies installed"
fi

echo ""
echo "✨ Development environment setup complete!"
echo ""
echo "🎯 Next steps:"
echo "   1. Edit backend/.env with your configuration"
echo "   2. Add JWT keys from backend/.keys/ to backend/.env"
echo "   3. Start backend: cd backend && cargo run --bin api_server"
echo "   4. Start frontend: cd frontend && npm run dev"
echo ""
echo "📊 Services:"
echo "   PostgreSQL: postgresql://idaas_user:dev_password_change_me@localhost:5432/idaas"
echo "   Redis: redis://localhost:6379"
echo "   pgAdmin: http://localhost:5050 (admin@idaas.local / admin)"
echo "   Redis Commander: http://localhost:8081"
echo ""
echo "🛠️  Useful commands:"
echo "   Stop services: docker-compose -f infrastructure/docker-compose/docker-compose.dev.yml down"
echo "   View logs: docker-compose -f infrastructure/docker-compose/docker-compose.dev.yml logs -f"
echo "   Reset database: docker-compose -f infrastructure/docker-compose/docker-compose.dev.yml down -v"
echo ""
