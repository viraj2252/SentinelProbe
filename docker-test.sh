#!/bin/bash
set -e

# Build and test the Docker container

echo "Step 1: Building the Docker image..."
docker build -t sentinelprobe:latest .

echo "Step 2: Creating a test container..."
docker run --name sentinelprobe-test -d \
  -p 8000:8000 \
  -e POSTGRES_SERVER=host.docker.internal \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=sentinelprobe \
  -e MONGODB_URL=mongodb://host.docker.internal:27017/sentinelprobe \
  -e REDIS_HOST=host.docker.internal \
  -e DEBUG=true \
  sentinelprobe:latest

echo "Step 3: Checking if container is running..."
sleep 5
CONTAINER_STATUS=$(docker ps -f name=sentinelprobe-test --format "{{.Status}}")

if [[ $CONTAINER_STATUS == *"Up"* ]]; then
  echo "✅ Container is running successfully!"
  echo "Container logs:"
  docker logs sentinelprobe-test
else
  echo "❌ Container failed to start"
  echo "Container logs:"
  docker logs sentinelprobe-test
  exit 1
fi

echo "Step 4: Cleaning up test container..."
docker stop sentinelprobe-test
docker rm sentinelprobe-test

echo "Docker test completed successfully!"
echo "To run the full application stack, use: docker-compose up -d"
