# System Design Document (SDD)

## 1. Introduction
This document provides the high-level architecture, data flow, and component design for **MicroAPI Guard**, an ML/DL-based API security gateway.

## 2. High-Level Architecture
The system follows a reverse-proxy gateway architecture, designed to intercept and analyze traffic without modifying backend microservices.

### Components
1.  **Traffic Simulator (Locust):** Generates synthetic user and attacker traffic.
2.  **API Gateway (FastAPI):** The core reverse proxy. Routes traffic, extracts features, and enforces inline blocking.
3.  **State Manager (Redis):** In-memory data store used to maintain a 60-second sliding window of request counts per client IP.
4.  **Backend Services (FastAPI Mock):** Represents the protected microservices (User, Product, Order).
5.  **Inference Engine:** Contains three base detectors (Static, Isolation Forest, Autoencoder) and a Logistic Regression meta-learner.
6.  **Security Dashboard (Streamlit):** Real-time monitoring UI.

## 3. Data Flow Diagram (DFD)

### 3.1 Level 0 Data Flow (Context)
*   `Client` sends HTTP Request $\rightarrow$ `API Gateway`
*   `API Gateway` checks `Inference Engine` $\rightarrow$ `Client` receives HTTP 403 (if Anomaly)
*   `API Gateway` forwards to `Backend` $\rightarrow$ `Backend` returns HTTP 200 (if Normal)

### 3.2 Level 1 Data Flow (Internal)
1.  **Intercept:** Gateway receives request.
2.  **State Update:** Gateway queries Redis (`ZADD`, `ZCARD`) for `window_count`.
3.  **Feature Extraction:** Gateway extracts 7 features (Method, Path, Size, Status, Duration, Window, Timestamp).
4.  **Inference:** Features are scaled and passed to IF, AE, and Static rules. Scores are aggregated by Logistic Regression.
5.  **Decision:** 
    *   If `Anomaly`: Return HTTP 403.
    *   If `Normal`: Forward to Backend, await response.
6.  **Logging:** Push features and scores to async queue, written to `api_traffic_features.jsonl`.

## 4. Data Models

### 4.1 Redis Schema
*   **Key:** `sw:{client_ip}` (e.g., `sw:192.168.1.5`)
*   **Type:** Sorted Set (ZSET)
*   **Score:** Epoch timestamp
*   **Value:** Epoch timestamp
*   **TTL:** 120 seconds

### 4.2 JSONL Dataset Schema (`api_traffic_features.jsonl`)
```json
{
  "timestamp": 1784923412.62,
  "client_ip": "172.18.0.1",
  "http_method": "POST",
  "http_path": "/api/orders",
  "request_body_size": 29,
  "response_status": 200,
  "request_duration_ms": 10.18,
  "sliding_window_count": 3,
  "is_anomaly": 0
}
```

## 5. Machine Learning Pipeline Design
1.  **Static Rules:** $Score = 1$ if `window_count` $> 50$, else $0$.
2.  **Isolation Forest:** Unsupervised ML model isolating anomalies in tree paths.
3.  **Autoencoder:** PyTorch DNN. Encoder compresses features, Decoder reconstructs. $Score = MSE(Input, Output)$.
4.  **Logistic Regression:** Meta-learner. $f(w_1*S_{static} + w_2*S_{if} + w_3*S_{ae} + b) \rightarrow \{0, 1\}$.
