# Setup and Deployment Guide

## Prerequisites
*   Docker & Docker Compose installed on the host machine.
*   Python 3.11+ (for running offline ML training and Locust).

## 1. Starting the MicroAPI Guard Framework
The entire environment (Gateway, Backend Microservices, Redis) is containerized using Docker Compose.

1.  Open a terminal and navigate to the `src` directory:
    ```bash
    cd d:\Final_Year_Project\src
    ```
2.  Build and start the containers in detached mode:
    ```bash
    docker-compose up -d --build
    ```
3.  Verify the services are running:
    ```bash
    docker-compose ps
    ```
    *You should see `microapi-gateway` (Port 5000), `microapi-backend` (Port 8000), and `microapi-redis` (Port 6379).*

## 2. Generating Traffic (Phase 2 Preview)
To simulate API traffic and populate the JSONL dataset:

1.  Install Locust locally:
    ```bash
    pip install locust
    ```
2.  Navigate to the simulation folder (once created in Phase 2):
    ```bash
    cd traffic_simulation
    locust -f locustfile.py
    ```
3.  Open the Locust web interface at `http://localhost:8089` and start the test against `http://localhost:5000`.

## 3. Viewing the Logs and Dataset
*   **Gateway Logs:** To view real-time request processing, latency, and window counts:
    ```bash
    docker logs microapi-gateway -f
    ```
*   **Dataset Retrieval:** The JSONL dataset is written inside the Gateway container. To view it:
    ```bash
    docker exec microapi-gateway cat api_traffic_features.jsonl
    ```

## 4. Stopping the Framework
To stop the containers without destroying the Redis data volume:
```bash
docker-compose stop
```
To stop and completely remove the containers:
```bash
docker-compose down
```
