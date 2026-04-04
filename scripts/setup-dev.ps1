# IDaaS Development Environment Setup Script (PowerShell)

Write-Host "🚀 Setting up IDaaS development environment..." -ForegroundColor Cyan

# Check for Container Engine (Docker or Podman)
$containerEngine = "docker"
if (Get-Command podman -ErrorAction SilentlyContinue) {
    $containerEngine = "podman"
}
elseif (!(Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Host "❌ No container engine (Docker or Podman) found. Please install Docker Desktop or Podman." -ForegroundColor Red
    exit 1
}

# Check if Container Engine is running
try {
    if ($containerEngine -eq "podman") {
        podman info | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Podman is not running" }
        Write-Host "✅ Podman is running" -ForegroundColor Green
    }
    else {
        docker info | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Docker is not running" }
        Write-Host "✅ Docker is running" -ForegroundColor Green
    }
}
catch {
    Write-Host "❌ $containerEngine is not running. Please start it and try again." -ForegroundColor Red
    # For Podman, sometimes specific machine start is needed
    if ($containerEngine -eq "podman") {
        Write-Host "💡 Hint: You might need to run 'podman machine start'" -ForegroundColor Yellow
        Write-Host "   Or check connection: podman system connection list" -ForegroundColor Gray
    }
    exit 1
}

# Detect Compose Command
$composeCommand = $null

# Try docker-compose
if (Get-Command docker-compose -ErrorAction SilentlyContinue) {
    $composeCommand = "docker-compose"
}

# Try podman-compose if not found
if ($null -eq $composeCommand) {
    if (Get-Command podman-compose -ErrorAction SilentlyContinue) {
        $composeCommand = "podman-compose"
    }
}

# Try podman compose if not found
if ($null -eq $composeCommand) {
    # Check if 'podman compose' works (Podman Desktop v5+ often includes this)
    # Capture output to check for specific provider errors
    $podmanComposeOutput = podman compose version 2>&1
    if ($LASTEXITCODE -eq 0) {
        $composeCommand = "podman compose"
    }
    elseif ($podmanComposeOutput -match "looking up compose provider failed") {
        # This is the specific error when podman-compose or docker-compose is missing
        Write-Host "❌ 'podman compose' found, but failed to find a provider." -ForegroundColor Red
        Write-Host "   It looks for 'docker-compose' or 'podman-compose' in your PATH." -ForegroundColor Yellow
        Write-Host "   Please install 'docker-compose' to fix this." -ForegroundColor Yellow
    }
}

if ($null -eq $composeCommand) {
    Write-Host "❌ No compose tool found." -ForegroundColor Red
    if ($containerEngine -eq "podman") {
        Write-Host "💡 For Podman, please install podman-compose:" -ForegroundColor Yellow
        Write-Host "   python -m pip install podman-compose" -ForegroundColor White
        Write-Host "   (Requires Python to be installed)" -ForegroundColor Gray
    }
    else {
        Write-Host "💡 Please install docker-compose." -ForegroundColor Yellow
    }
    exit 1
}

Write-Host "✅ Found compose command: $composeCommand" -ForegroundColor Green

# Check if Rust is installed
if (Get-Command cargo -ErrorAction SilentlyContinue) {
    $rustVersion = cargo --version
    Write-Host "✅ Rust is installed: $rustVersion" -ForegroundColor Green
}
else {
    Write-Host "❌ Rust is not installed. Install from https://rustup.rs/" -ForegroundColor Red
    exit 1
}

# Check if Node.js is installed
if (Get-Command node -ErrorAction SilentlyContinue) {
    $nodeVersion = node --version
    Write-Host "✅ Node.js is installed: $nodeVersion" -ForegroundColor Green
}
else {
    Write-Host "❌ Node.js is not installed. Install from https://nodejs.org/" -ForegroundColor Red
    exit 1
}

# Start Docker services
Write-Host "📦 Starting Docker services..." -ForegroundColor Cyan
Set-Location infrastructure\docker-compose
# Execute the compose command
if ($composeCommand -eq "podman compose") {
    podman compose -f docker-compose.dev.yml up -d
}
else {
    & $composeCommand -f docker-compose.dev.yml up -d
}
Set-Location ..\..

Write-Host "⏳ Waiting for services to be healthy..." -ForegroundColor Yellow
Start-Sleep -Seconds 10

# Check database connection
Write-Host "🔍 Checking PostgreSQL connection..." -ForegroundColor Cyan
if ($containerEngine -eq "podman") {
    podman exec idaas-postgres-dev pg_isready -U idaas_user -d idaas
}
else {
    docker exec idaas-postgres-dev pg_isready -U idaas_user -d idaas
}

# Install sqlx-cli if not present
if (!(Get-Command sqlx -ErrorAction SilentlyContinue)) {
    Write-Host "📥 Installing sqlx-cli..." -ForegroundColor Cyan
    cargo install sqlx-cli --no-default-features --features postgres
}
Write-Host "✅ sqlx-cli is installed" -ForegroundColor Green

# Copy environment file if not exists
if (!(Test-Path backend\.env)) {
    Write-Host "📝 Creating backend\.env from template..." -ForegroundColor Cyan
    Copy-Item backend\.env.example backend\.env
    Write-Host "⚠️  Please edit backend\.env with your configuration" -ForegroundColor Yellow
}

# Run database migrations
Write-Host "🗄️  Running database migrations..." -ForegroundColor Cyan
Set-Location backend
$env:DATABASE_URL = "postgres://idaas_user:dev_password_change_me@localhost:5432/idaas"
sqlx migrate run --source crates/db_migrations/migrations
Set-Location ..
Write-Host "✅ Database migrations completed" -ForegroundColor Green

# Generate JWT keys for development
Write-Host "🔐 Generating development JWT keys..." -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path backend\.keys | Out-Null

if (!(Test-Path backend\.keys\private.pem)) {
    openssl ecparam -genkey -name prime256v1 -noout -out backend\.keys\private.pem
    openssl ec -in backend\.keys\private.pem -pubout -out backend\.keys\public.pem
    Write-Host "✅ JWT keys generated in backend\.keys\" -ForegroundColor Green
    Write-Host "⚠️  Add these to your backend\.env file" -ForegroundColor Yellow
}

# Install frontend dependencies
if (Test-Path frontend) {
    Write-Host "📦 Installing frontend dependencies..." -ForegroundColor Cyan
    Set-Location frontend
    if (!(Test-Path .env)) {
        if (Test-Path .env.example) {
            Copy-Item .env.example .env
        }
        else {
            "VITE_API_URL=http://localhost:3000" | Out-File -Encoding UTF8 .env
        }
    }
    npm install
    Set-Location ..
    Write-Host "✅ Frontend dependencies installed" -ForegroundColor Green
}

Write-Host ""
Write-Host "✨ Development environment setup complete!" -ForegroundColor Green
Write-Host ""
Write-Host "🎯 Next steps:" -ForegroundColor Cyan
Write-Host "   1. Edit backend\.env with your configuration"
Write-Host "   2. Add JWT keys from backend\.keys\ to backend\.env"
Write-Host "   3. Start backend: cd backend && cargo run --bin api_server"
Write-Host "   4. Start frontend: cd frontend && npm run dev"
Write-Host ""
Write-Host "📊 Services:" -ForegroundColor Cyan
Write-Host "   PostgreSQL: postgresql://idaas_user:dev_password_change_me@localhost:5432/idaas"
Write-Host "   Redis: redis://localhost:6379"
Write-Host "   pgAdmin: http://localhost:5050 (admin@idaas.local / admin)"
Write-Host "   Redis Commander: http://localhost:8081"
Write-Host ""
Write-Host "🛠️  Useful commands:" -ForegroundColor Cyan
Write-Host "   Stop services: $composeCommand -f infrastructure\docker-compose\docker-compose.dev.yml down"
Write-Host "   View logs: $composeCommand -f infrastructure\docker-compose\docker-compose.dev.yml logs -f"
Write-Host "   Reset database: $composeCommand -f infrastructure\docker-compose\docker-compose.dev.yml down -v"
Write-Host ""
