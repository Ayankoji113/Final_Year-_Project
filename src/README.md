# MicroAPI Guard

> AI-Based Anomaly Detection Framework for API Traffic in Microservice Architectures

## Quick Start

```bash
docker-compose up --build
```

## Services

| Service | Port | Description |
|---------|------|-------------|
| Gateway | 5000 | FastAPI API Gateway (Reverse Proxy) |
| Backend | 8000 | Mock Microservices (User, Product, Order) |
| Redis   | 6379 | Sliding Window State Store |

## Test

```bash
# Get all products (through gateway)
curl http://localhost:5000/api/products

# Login (through gateway)
curl -X POST http://localhost:5000/api/users/login -H "Content-Type: application/json" -d '{"username":"admin","password":"pass123"}'

# Place order (through gateway)
curl -X POST http://localhost:5000/api/orders -H "Content-Type: application/json" -d '{"product_id":1,"quantity":2}'
```
