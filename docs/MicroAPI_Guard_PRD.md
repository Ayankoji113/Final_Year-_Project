# Product Requirements Document (PRD)

## 1. Project Information
* **Project Name:** MicroAPI Guard
* **Tagline:** Real-Time API Anomaly Detection Using ML and DL
* **Project Type:** Academic B.Tech Project / Open Source Security Tool
* **Status:** In Development (Phase 1 Completed)

## 2. Product Vision & Objective
With the widespread adoption of microservice architectures, REST APIs have become primary targets for cyberattacks. Traditional API security mechanisms (like WAFs and static rate-limiters) often incorrectly block legitimate traffic during spikes and fail to detect sophisticated low-and-slow attacks. 

**MicroAPI Guard** aims to bridge the gap between academic machine learning research and production-grade API security. It is a deployable, open-source API security gateway that performs real-time traffic interception and uses a **Learned Stacking Ensemble** (Static Rules, Isolation Forest, Deep Autoencoder + Logistic Regression) to detect and block malicious requests inline before they reach backend microservices, all without requiring modifications to the backend source code.

## 3. Target Audience / User Personas
* **DevSecOps Engineers / SREs:** Need a transparent, easy-to-deploy API gateway to protect their microservices from DDoS, credential stuffing, and payload anomalies.
* **Security Researchers:** Require an open framework to evaluate different machine learning and deep learning anomaly detection models on API traffic.
* **Backend Developers:** Need API security that can be placed in front of their applications (Node.js, Spring Boot, FastAPI) without changing application logic.

## 4. Key Features & Functional Requirements

### 4.1 Traffic Interception & Reverse Proxy
* **REQ-1.1:** The gateway must act as a reverse proxy, accepting incoming HTTP requests and forwarding them to the destination backend.
* **REQ-1.2:** The gateway must operate independently of the backend tech stack.
* **REQ-1.3:** The gateway must handle API routing dynamically.

### 4.2 Real-Time Feature Extraction
* **REQ-2.1:** Extract payload characteristics: Request method, URL path, and payload size (bytes).
* **REQ-2.2:** Compute behavioral metrics: Maintain a sliding window using Redis to track request rates per client IP over a 60-second window.
* **REQ-2.3:** Calculate payload entropy (Shannon entropy) to detect obfuscated or malicious payloads.
* **REQ-2.4:** Output extracted features asynchronously to a JSONL dataset for offline training and forensic logging.

### 4.3 Machine Learning Inference Engine
* **REQ-3.1 (Base Detectors):** Run incoming feature vectors through three parallel detectors:
  1. Static Rules Engine (Threshold-based)
  2. Isolation Forest (Machine Learning)
  3. Deep Autoencoder (Deep Learning)
* **REQ-3.2 (Meta-Learner):** Pass the anomaly scores from the base detectors to a Logistic Regression meta-learner to generate a final binary prediction (Normal/Anomaly).
* **REQ-3.3 (Latency):** The entire inference process (feature extraction + model evaluation) must add minimal latency (target < 20ms) to the request round trip.

### 4.4 Inline Threat Mitigation
* **REQ-4.1:** If the meta-learner classifies a request as "Anomaly", the gateway must instantly block the request and return an `HTTP 403 Forbidden` response to the client.
* **REQ-4.2:** If classified as "Normal", the gateway must seamlessly return the backend's response to the client.

### 4.5 System Calibration Phase
* **REQ-5.1:** Allow the gateway to run in a "Calibration Mode" upon deployment to a new environment.
* **REQ-5.2:** Observe benign traffic for a short duration to establish behavioral baselines and adjust statistical thresholds without requiring a full model retraining from scratch.

### 4.6 Monitoring & Dashboarding
* **REQ-6.1:** Provide a real-time web dashboard.
* **REQ-6.2:** Display live traffic statistics (Total Requests, Blocked vs. Forwarded).
* **REQ-6.3:** Provide explainability by displaying the individual anomaly scores of the three base detectors for flagged requests.

## 5. Non-Functional Requirements
* **Performance:** Gateway inference overhead should not exceed 20ms per request. The sliding window state must be retrieved in < 2ms using Redis.
* **Scalability:** The architecture must be fully containerized (Docker) to allow horizontal scaling of the FastAPI gateway.
* **Transparency:** The solution must be fully open-source, avoiding the "black-box" nature of commercial Enterprise WAFs.
* **Resiliency:** If Redis fails, the gateway should gracefully fallback (disabling sliding window but continuing to route traffic). If the backend is down, the gateway should return `HTTP 503`.

## 6. Technology Stack
* **Core Gateway:** Python 3.11+, FastAPI, Uvicorn, HTTPX
* **State Management:** Redis (Asyncio)
* **Machine Learning:** Scikit-Learn (Isolation Forest, Logistic Regression), Statsmodels (McNemar test)
* **Deep Learning:** PyTorch (Autoencoder)
* **Data Generation:** Locust (Traffic simulation and attack generation)
* **Visualization:** Streamlit
* **Containerization:** Docker & Docker Compose

## 7. Architecture Overview
1. **Traffic Generation:** Locust simulates normal and attack traffic.
2. **Entry Point:** FastAPI Gateway intercepts the request.
3. **State Check:** Queries Redis for historical client behavior (Sliding Window).
4. **Inference:** Pre-trained ML/DL models evaluate the request features.
5. **Action:** Forward to Backend OR Block (HTTP 403).
6. **Logging:** Async queue writes request features and model scores to a JSONL file.
7. **Visualization:** Streamlit dashboard reads the JSONL file to display metrics.

## 8. Milestones & Timeline
* **Phase 1: Infrastructure & Gateway Setup (Completed)**
  * Basic reverse proxy, mock backends, Redis sliding window, and JSONL logging.
* **Phase 2: Dataset Generation**
  * Develop Locust scripts to simulate normal users (state machines) and attackers (flooding, large payloads) to generate the training dataset.
* **Phase 3: ML Training & Stacking Ensemble**
  * Train the Isolation Forest, Autoencoder, and Logistic Regression models offline using the generated JSONL dataset.
* **Phase 4: Real-time Inference & Dashboarding**
  * Load pre-trained models into the FastAPI gateway for live blocking. Build the Streamlit dashboard for explainability.
* **Phase 5: Evaluation & Documentation**
  * Statistical validation (McNemar test, ROC-AUC) and final project report formatting.
