# Installation Guide

This guide will walk you through the process of installing SentinelProbe for both development and production environments.

## Prerequisites

Before installing SentinelProbe, ensure you have the following prerequisites:

- Python 3.10 or higher
- Docker and Docker Compose (for containerized deployments)
- PostgreSQL 13+ (for production deployments)
- MongoDB 5.0+ (for production deployments)
- Redis (optional, for caching and performance optimization)
- Git (for cloning the repository)

## Development Installation

### 1. Clone the Repository

```bash
git clone https://github.com/viraj2252/sentinelprobe.git
cd sentinelprobe
```

### 2. Set Up Python Environment with Poetry

SentinelProbe uses Poetry for dependency management:

```bash
# Install Poetry if you haven't already
curl -sSL https://install.python-poetry.org | python3 -

# Install dependencies
poetry install

# Activate the virtual environment
poetry shell
```

### 3. Set Up Development Databases

For development, you can use Docker to run PostgreSQL and MongoDB:

```bash
# Start the development databases
docker-compose up -d postgres mongodb
```

### 4. Configure Environment Variables

Copy the example environment file and adjust it for your environment:

```bash
cp .env.example .env

# Edit the .env file with your database credentials and other settings
nano .env
```

### 5. Run Database Migrations

```bash
# Inside the poetry shell
python -m sentinelprobe migrate
```

### 6. Run the Development Server

```bash
# Inside the poetry shell
python -m sentinelprobe run
```

## Production Installation

### 1. Clone the Repository

```bash
git clone https://github.com/viraj2252/sentinelprobe.git
cd sentinelprobe
```

### 2. Configure Environment Variables

Create a production `.env` file:

```bash
cp .env.example .env.production

# Edit the .env.production file with your production settings
nano .env.production
```

### 3. Docker-based Deployment

SentinelProbe can be deployed using Docker Compose for production:

```bash
# Build the Docker images
docker-compose -f docker-compose.yml -f docker-compose.prod.yml build

# Start the services
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

### 4. Kubernetes Deployment (Optional)

For larger deployments, Kubernetes is recommended:

```bash
# Apply Kubernetes manifests
kubectl apply -f kubernetes/
```

## Verifying the Installation

### Check if Services are Running

```bash
# For Docker-based installations
docker-compose ps

# For Kubernetes installations
kubectl get pods
```

### Access the API

The API should be available at `http://localhost:8000` (or your configured address).

### Run Tests

Verify the installation by running the test suite:

```bash
# Inside the poetry shell
pytest
```

## Troubleshooting

### Common Issues

#### Database Connection Errors

Ensure your database credentials are correct in the `.env` file and that the database services are running.

```bash
# Check if PostgreSQL is running
docker-compose ps postgres

# Check if MongoDB is running
docker-compose ps mongodb
```

#### Permission Issues

If you encounter permission issues with the databases or logs, ensure the proper permissions are set:

```bash
# Fix permissions for logs directory
sudo chown -R $(whoami) logs/

# Fix permissions for database volumes
sudo chown -R $(whoami) path/to/db/volumes
```

#### Port Conflicts

If you encounter port conflicts, you can modify the ports in the `docker-compose.yml` file or your environment variables.

## Next Steps

After installation, see the [Quick Start Tutorial](quick-start.md) to learn how to use SentinelProbe for your first scan.
