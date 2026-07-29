# MicroAPI Guard

**Real-Time API Anomaly Detection Using ML and DL**
An intelligent, open-source API security gateway that intercepts traffic and uses a Learned Stacking Ensemble (Static Rules, Isolation Forest, and Deep Autoencoders) to detect and block malicious requests inline before they reach backend microservices.

## Table of Contents
- [About](#about)
- [Features](#features)
- [Tech Stack](#tech-stack)
- [Architecture](#architecture)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Local Setup](#local-setup)
- [Configuration](#configuration)
- [Usage](#usage)
- [Deployment](#deployment)
- [Contributing](#contributing)
- [Roadmap](#roadmap)
- [License](#license)
- [Contact](#contact)

## About
With the widespread adoption of microservice architectures, REST APIs have become primary targets for cyberattacks. Traditional API security mechanisms (like WAFs and static rate-limiters) often incorrectly block legitimate traffic during spikes and fail to detect sophisticated low-and-slow attacks.

**MicroAPI Guard** aims to bridge the gap between academic machine learning research and production-grade API security. It acts as a transparent reverse proxy that extracts behavioral features and payload entropy in real-time, feeding them into a multi-layered machine learning model for robust inline threat mitigation—all without requiring any modifications to your backend source code.

## Features
- **Transparent Reverse Proxy** — Operates completely independent of the backend tech stack, intercepting and routing requests seamlessly.
- **Real-Time Feature Extraction** — Computes behavioral metrics (like sliding-window request rates via Redis) and payload entropy on the fly.
- **Learned Stacking Ensemble** — Utilizes three parallel base detectors (Static Rules Engine, Scikit-Learn Isolation Forest, and PyTorch Deep Autoencoder) combined through a Logistic Regression meta-learner for high accuracy.
- **Inline Threat Mitigation** — Blocks anomalous requests instantly (HTTP 403) with a minimal latency overhead (target < 20ms).
- **Monitoring & Explainability** — Comes with a Streamlit dashboard that visualizes live traffic statistics and provides explainability through individual anomaly scores.

## Tech Stack
- **Core Gateway:** Python 3.11+, FastAPI, Uvicorn, HTTPX
- **State Management:** Redis (Asyncio)
- **Machine Learning & Deep Learning:** Scikit-Learn, PyTorch, Statsmodels
- **Traffic Simulation:** Locust
- **Visualization:** Streamlit
- **Containerization:** Docker & Docker Compose

## Architecture
The system consists of the following components and interactions:
1. **Traffic Generation:** Clients or Locust scripts send API requests (normal and malicious).
2. **Entry Point (FastAPI Gateway):** Intercepts incoming requests.
3. **State Check:** Queries Redis for historical client behavior (60-second sliding window).
4. **Inference:** Extracts features and evaluates them against the pre-trained ML/DL Stacking Ensemble.
5. **Action:** If benign, forwards the request to the Backend API and returns the response. If anomalous, blocks with HTTP 403.
6. **Logging:** Request features and scores are asynchronously logged to a JSONL dataset.
7. **Dashboard:** Streamlit reads the JSONL logs to provide real-time monitoring and explainability.

## Getting Started

### Prerequisites
- Python >= 3.11
- Redis Server (running locally or via Docker)
- Docker & Docker Compose (Recommended for easy setup)
- Git

### Local Setup

1. **Clone the repo:**
   ```bash
   git clone https://github.com/Ayankoji113/Final_Year-_Project.git
   cd Final_Year-_Project
   ```

2. **Run with Docker Compose (Recommended):**
   This will spin up the Gateway, Mock Backend, Redis, and Streamlit Dashboard simultaneously.
   ```bash
   cd src
   docker-compose up --build
   ```

3. **Manual Local Setup (Alternative):**
   *Terminal 1 - Redis:*
   Ensure Redis is running on `localhost:6379`.

   *Terminal 2 - Mock Backend:*
   ```bash
   cd src/backend
   pip install -r requirements.txt
   uvicorn main:app --reload --port 8001
   ```

   *Terminal 3 - Gateway:*
   ```bash
   cd src/gateway
   pip install -r requirements.txt
   uvicorn main:app --reload --port 8000
   ```

## Configuration
Configuration variables can be passed as Environment Variables or stored in a `.env` file in the `src/gateway` directory.
- `REDIS_URL` = `redis://localhost:6379` (or `redis://redis:6379` in Docker)
- `BACKEND_URL` = `http://localhost:8001` (or `http://backend:8001` in Docker)
- `PORT` = `8000` (Gateway Port)

## Usage
- **Normal Request:**
  Send a GET request to the gateway:
  ```bash
  curl http://localhost:8000/api/data
  ```
  *Response should be passed through from the backend.*

- **Simulating Attack Traffic:**
  Use the provided Locust script to generate traffic datasets or test the mitigation inline.
  ```bash
  cd src/traffic_simulator
  pip install -r requirements.txt
  locust -f locustfile.py
  ```
  Open `http://localhost:8089` to start the swarm.

## Deployment
MicroAPI Guard is fully containerized. You can deploy it to any cloud provider (AWS EC2, DigitalOcean Droplets, Google Cloud Run) by utilizing the provided `docker-compose.yml`.
```bash
cd src
docker-compose up -d --build
```

## Contributing
1. Fork the repo
2. Create a new branch: `git checkout -b feat/your-feature-name`
3. Commit your changes: `git commit -m "feat: add some feature"`
4. Push to the branch: `git push origin feat/your-feature-name`
5. Open a Pull Request

## Roadmap
- **Phase 1:** Infrastructure & Gateway Setup (Completed)
- **Phase 2:** Dataset Generation using Locust
- **Phase 3:** ML Training & Stacking Ensemble implementation
- **Phase 4:** Real-time Inference & Dashboarding
- **Phase 5:** Evaluation & Statistical Validation (McNemar test, ROC-AUC)

## License
This project is open-source and intended for academic and security research purposes.

## Contact
- **Maintainer:** @Ayankoji113
- **Project Link:** [https://github.com/Ayankoji113/Final_Year-_Project](https://github.com/Ayankoji113/Final_Year-_Project)