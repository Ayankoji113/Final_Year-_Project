# MicroAPI Guard - Phases 2 to 5 Implementation Plan

This document outlines the complete plan to build the remaining 80% of the project.

## Goal Description
The objective is to complete the MicroAPI Guard framework by simulating traffic, training the machine learning and deep learning models, integrating them into the FastAPI gateway for real-time blocking, and building a monitoring dashboard.

---

## Proposed Changes

### 1. Phase 2: Dataset Generation (Traffic Simulation)
To train our anomaly detection models, we need a dataset containing both normal and attack traffic.
*   **Gateway Update:** Modify `src/gateway/main.py` to capture a ground-truth label (e.g., `X-Simulated-Attack: 1`) injected by the traffic generator and save it into the JSONL file as `is_anomaly`.
*   **Locust Scripts:** Create `src/traffic_simulation/locustfile.py`.
    *   **Normal Behavior:** Simulates users logging in, browsing products, and placing orders.
    *   **Attack Behavior:** Simulates DDoS (high request rate), Credential Stuffing (rapid failed logins), and Large Payloads.

### 2. Phase 3: ML Training & Stacking Ensemble
Develop the offline machine learning pipeline to train the models on the generated dataset.
*   **Data Preparation:** Create `src/ml_pipeline/train.py`. Load `api_traffic_features.jsonl`, encode categorical features (`http_method`, `http_path`), and split the data (Training on normal data only; Validation and Testing on a mix of normal and attack data).
*   **Base Detectors:**
    *   `Static Rules`: Threshold-based baseline (e.g., sliding window count > threshold).
    *   `Isolation Forest`: Train using `scikit-learn` on normal data.
    *   `Deep Autoencoder`: Train using `PyTorch` (Encoder-Decoder architecture) to minimize reconstruction error on normal data.
*   **Meta-Learner:** Extract continuous anomaly scores from the three base detectors on the Validation set. Train a `Logistic Regression` model to combine these scores into a final prediction (`Normal` or `Anomaly`).
*   **Model Export:** Save the trained models (`.pkl` and `.pth` files) and scalers.

### 3. Phase 4: Real-Time Inference & Blocking
Integrate the trained models into the live gateway for active protection.
*   **Gateway Update:** Modify `src/gateway/main.py` to load the trained ML models on startup.
*   **Inline Inference:** For every incoming request:
    1.  Extract features.
    2.  Generate scores from Static Rules, IF, and Autoencoder.
    3.  Pass scores to the Logistic Regression meta-learner.
*   **Actionable Blocking:** If the meta-learner predicts an anomaly, the gateway instantly returns `HTTP 403 Forbidden` and prevents the request from reaching the backend. Otherwise, it forwards the request.
*   **Logging:** Record the individual model scores and the final action (Blocked/Forwarded) in the JSONL logs.

### 4. Phase 5: Explainable Security Dashboard
Build a real-time monitoring interface.
*   **Streamlit App:** Create `src/dashboard/app.py`.
*   **Metrics & Visualization:** Read the live JSONL file to display traffic volume, blocked vs. forwarded request ratios, and a forensic view of why requests were blocked (visualizing the base detector scores).
*   **Docker Integration:** Update `docker-compose.yml` to run the Streamlit dashboard as a service alongside the Gateway, Backend, and Redis.

---

## Verification Plan

### Automated Tests
- Run Locust to generate ~10,000 requests.
- Run `train.py` and verify models are generated and evaluation metrics (Precision, Recall, F1-score) are outputted.
- Inject attack payloads to the live Gateway and verify an immediate `403 Forbidden` response.

### Manual Verification
- Open the Streamlit dashboard (`http://localhost:8501`) and visually confirm that attack traffic is being flagged and blocked in real-time.
