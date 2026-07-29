# Q1. Problem Identification & Justification

## Problem Identification

APIs (Application Programming Interfaces) are among the most critical and widely targeted components in modern cloud-native and microservice-based applications. They serve as the primary communication channel between distributed services, mobile clients, and third-party integrations. APIs can be exploited in numerous ways, including unauthorized data access, injection attacks, credential stuffing, and distributed denial-of-service (DDoS) attacks. A single compromised API endpoint can expose sensitive user data, disrupt business operations, and lead to significant financial and reputational damage.

RESTful API communication is the dominant standard in microservice architectures because it provides lightweight, stateless, and scalable interactions between services. Modern applications may consist of hundreds of independently deployed microservices, each exposing multiple API endpoints. This architectural choice, while offering tremendous flexibility, creates an exponentially larger attack surface compared to traditional monolithic applications. A single user session may trigger dozens of inter-service API calls, making it practically impossible to manually inspect each request for malicious intent.

Currently, API security is primarily managed by traditional tools such as static rate limiters, Web Application Firewalls (WAFs), and signature-based intrusion detection systems. These tools rely heavily on predefined rules and known attack signatures written and maintained by security engineers. In enterprise environments with high API traffic volumes, security teams often work under significant pressure and time constraints, increasing the possibility of misconfigured rules or delayed response to emerging threats. Furthermore, different security teams may interpret the same traffic pattern differently, leading to inconsistent security policies across services and unreliable threat detection.

Recent advancements in Artificial Intelligence (AI), Machine Learning (ML), and Deep Learning (DL) have significantly transformed the field of network security and anomaly detection. Unsupervised learning models, particularly Isolation Forest and Deep Autoencoders, have demonstrated outstanding performance in identifying statistical outliers without requiring labeled attack data. Advanced ensemble techniques such as Stacking Ensembles, where multiple base detectors are combined through a meta-learner, have further improved detection accuracy while reducing false positive rates. These approaches enable adaptive, data-driven security that can learn the characteristics of legitimate traffic and flag deviations automatically.

---

## Specific Challenges

The development of an AI-based API security gateway for microservice architectures introduces several technical, operational, and computational challenges that affect detection accuracy, system reliability, and deployment feasibility. The major challenges addressed by the MicroAPI Guard framework are as follows:

### 1. Manual Rule Maintenance
Traditional API security relies on manually written firewall rules and signature databases. Security engineers must continuously update these rules as new attack vectors emerge. In large-scale microservice deployments with hundreds of endpoints, maintaining accurate and up-to-date rules becomes extremely labor-intensive, error-prone, and unsustainable.

### 2. Static Rate-Limiting Inefficiency
Conventional rate-limiting enforces a fixed quota of API calls per client per time window. However, sophisticated attackers distribute their requests across multiple clients or IP addresses to stay below individual thresholds. Additionally, setting thresholds too aggressively can block legitimate users during natural traffic spikes, leading to unacceptable false positive rates.

### 3. Heterogeneous Traffic Patterns
API traffic in microservice environments is inherently heterogeneous. Different services exhibit vastly different request patterns in terms of frequency, payload size, response time, and HTTP methods used. A single, static detection model trained on one service's traffic often fails to generalize across the entire API infrastructure, requiring per-service tuning.

### 4. Limited Explainability of Detection Models
Most machine learning-based intrusion detection systems function as "black-box" models, providing a binary normal/anomaly label without explaining which specific feature or behavior triggered the alert. In production security operations, engineers require transparency and interpretability before acting on automated threat alerts.

### 5. High Latency Overhead of ML Inference
Deploying machine learning models in the critical path of API request processing introduces latency overhead. If the anomaly detection pipeline is not optimized for real-time inference, it can degrade the overall response time of the protected backend services, making the security gateway itself a performance bottleneck.

### 6. Lack of Adaptive Calibration Mechanisms
Most existing ML-based intrusion detection systems are trained on static, historical datasets and deployed with fixed thresholds. They lack an automated calibration mechanism to adapt their baseline to a new, unseen backend environment. When deployed on a different microservice architecture, these models require complete retraining, which is impractical in dynamic production environments.

### 7. Single-Model Detection Limitations
Relying on a single anomaly detection algorithm introduces inherent blind spots. For example, Isolation Forest excels at detecting statistical outliers but may miss attacks that mimic normal statistical distributions. Similarly, Autoencoders detect reconstruction-based anomalies but may not catch simple rate-based abuse. No single algorithm can comprehensively cover all attack categories.

---

## Justification

The proposed MicroAPI Guard framework is justified because existing API security solutions primarily rely on static rules and signature matching and lack an integrated, intelligent detection pipeline. Commercial solutions such as Wallarm, Salt Security, and AWS WAF offer enhanced protection but come with steep licensing costs, vendor lock-in, and opaque detection methodologies that limit transparency and reproducibility. Although significant research has been conducted on Isolation Forests, Autoencoders, and ensemble methods individually, these techniques are generally evaluated in isolation and do not provide a unified, deployable framework for real-time API traffic protection in microservice environments.

MicroAPI Guard introduces an intelligent and integrated API security gateway that combines a Learned Stacking Ensemble of three parallel detection models with automated calibration to provide accurate and adaptive anomaly detection for live API traffic. The framework incorporates real-time feature extraction using Redis sliding windows, parallel anomaly scoring by a Static Rate Limiter, Isolation Forest, and Deep Autoencoder, and a Logistic Regression meta-learner that combines the three scores into a final classification. By integrating these components into a unified, low-latency gateway, MicroAPI Guard enhances detection accuracy, reduces false positives, and provides full transparency into the decision-making process through a real-time Streamlit monitoring dashboard.

---

## Novel Contributions of MicroAPI Guard

1. Learned Stacking Ensemble combining three heterogeneous anomaly detectors (Statistical, ML, and DL) through a Logistic Regression meta-learner for robust API threat detection.
2. Real-time feature extraction pipeline using Redis sliding-window counters for per-client behavioral analysis with minimal latency overhead.
3. Automated calibration mechanism that learns legitimate traffic patterns of any new backend, eliminating the need for complete model retraining upon deployment.
4. Transparent and explainable detection through a real-time Streamlit dashboard that visualizes individual model scores and highlights which specific detector triggered the alert.
5. Synthetic dataset generation framework using Locust load-testing tool to simulate realistic normal and attack traffic patterns for model training.
6. Lightweight, deployable microservice architecture built with FastAPI and Docker, suitable for integration with any backend technology stack.
7. Parallel multi-model inference pipeline maintaining sub-20ms added latency per request, ensuring production-grade performance.
8. Scalable and portable design demonstrated by applying the same trained models to different backend systems with minimal recalibration.
