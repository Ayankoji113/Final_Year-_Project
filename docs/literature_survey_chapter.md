# Chapter 2: Literature Survey

## 2.1 Introduction
A comprehensive literature review was conducted to understand the current state-of-the-art in API security, microservice observability, and machine learning-based anomaly detection. The research papers surveyed in this chapter were sourced from prominent digital libraries and publisher databases, including **IEEE Xplore, ACM Digital Library, ScienceDirect, and Springer**. The reviewed literature can be broadly categorized into three domains: general anomaly detection in microservices, API-specific traffic monitoring, and the application of advanced AI/ML models for intrusion detection.

## 2.2 Anomaly Detection in Microservice Architectures
Microservices generate vast amounts of telemetry data (logs, metrics, and traces), making them a primary focus for automated anomaly detection and Root Cause Analysis (RCA). 

Several studies have explored the challenges of observability in these distributed environments. A foundational survey on *Anomaly detection and root-cause identification in microservices* highlights the sheer volume of inter-service communication as a major hurdle. Similarly, research into *Observability in Microservices: An In-Depth Exploration of Frameworks, Challenges, and Deployment Paradigms* emphasizes the need for lightweight monitoring solutions that do not introduce high overhead.

To handle the complexity of telemetry data, researchers have proposed various statistical and machine learning methods. For instance, the *Anomaly Detection Algorithm for Microservice Architecture Based on Robust Principal Component Analysis* utilizes dimensionality reduction to identify statistical deviations in service metrics. However, real-world systems often suffer from missing data. Addressing this, the *ADmM (Anomaly Detection for Microservice Systems with Incomplete Metrics)* framework was proposed to maintain detection accuracy even when metric collection fails partially.

More recent approaches have shifted towards deep learning and graph-based representations. The *LMGD* model proposes a Log-Metric Combined approach using Graph-Based Deep Learning to correlate different telemetry types. Similarly, *Unsupervised detection of microservice trace anomalies through service-level deep Bayesian networks* demonstrates the efficacy of probabilistic models in identifying abnormal execution paths across distributed traces without relying on labeled attack data.

## 2.3 API Security and Gateway-Level Monitoring
While general microservice observability focuses on internal health (CPU, memory, traces), API security focuses explicitly on external and inter-service HTTP traffic. 

The API Gateway is widely recognized as the optimal placement for security enforcement. Research on the *Design and application of an intelligent API gateway for traffic anomaly detection* demonstrates that intercepting traffic at the edge reduces the computational burden on downstream services. A highly relevant study, *API Traffic Anomaly Detection in Microservice Architecture*, validates the use of machine learning algorithms directly on HTTP traffic features to identify malicious requests.

Other works approach API security from a specification and compliance perspective. *API Security Based on Automatic OpenAPI Mapping* suggests automatically generating security constraints based on OpenAPI specifications to detect non-compliant traffic. In broader cloud contexts, frameworks like the *SaaS API Monitoring for Data Leakage and Access Anomalies* focus on behavioral analytics to ensure privacy and detect data exfiltration, highlighting that API abuse is not just about rate limits, but also about abnormal data access patterns.

## 2.4 Advanced AI Techniques for Intrusion Detection
The literature shows a clear trend towards utilizing advanced and hybrid AI techniques to counter sophisticated cyber threats, such as zero-day attacks.

**Tree-Based and Reconstruction Models:** 
The use of Isolation Forests and Autoencoders has gained significant traction due to their unsupervised nature. The *Insider Threat Detection Model using Anomaly-Based Isolation Forest Algorithm* showcases the algorithm's ability to efficiently isolate abnormal behavioral patterns. Expanding on this, the paper *Intrusion Detection Based on Autoencoder and Isolation Forest in Fog Computing* explores the combination of deep learning (Autoencoders for feature reconstruction) and statistical isolation (Isolation Forest) in decentralized environments, providing a strong theoretical basis for using these algorithms in tandem.

**Next-Generation Paradigms (RL, LLMs, FL, KGs):**
Researchers are increasingly experimenting with cutting-edge AI paradigms. *Adaptive Defense: Zero-Day Attack Detection in NIDS With Deep Reinforcement Learning* introduces continuous learning mechanisms to adapt to new attack vectors. *Asynchronous Real-Time Federated Learning for Anomaly Detection* addresses privacy concerns by training models across distributed microservice clouds without sharing raw traffic data. 

Furthermore, the integration of context and semantics is being explored through Large Language Models (LLMs) and Knowledge Graphs. Studies like *Toward Context-Aware Anomaly Detection for AIOps using Dynamic Knowledge Graphs* and *Anomaly Detection and Root Cause Analysis Using Large Language Models and Bayesian Networks* demonstrate that adding contextual relationships improves the explainability and accuracy of anomaly alerts.

## 2.5 Research Gap and Proposed Contribution
Despite the extensive research in this domain, several critical gaps remain:
1. **Lack of Ensembled Real-Time Evaluation:** While papers explore Isolation Forests and Autoencoders individually, very few implement a *Learned Stacking Ensemble* (e.g., using a Logistic Regression meta-learner) that dynamically combines the strengths of multiple unsupervised models in real-time.
2. **Heavyweight Deployments:** Many proposed solutions (like those relying on LLMs, Graph Neural Networks, or complex tracing pipelines) require massive computational resources (GPUs, heavy data pipelines), making them unsuitable for lightweight, high-throughput API Gateways.
3. **Absence of Calibration:** Most machine learning models in NIDS are trained on static, historical datasets. They lack a "Calibration Phase" to automatically adapt baseline thresholds to a newly deployed, unseen backend architecture without manual retraining.

**Contribution of MicroAPI Guard:**
This project directly addresses these gaps by proposing a highly deployable, lightweight API security gateway. Instead of relying on a single algorithm, it utilizes a **Learned Stacking Ensemble** combining Static Rate Limiting, Isolation Forest, and a Deep Autoencoder. By employing a Logistic Regression meta-learner and a rapid Redis-backed feature extraction pipeline, the system achieves the accuracy benefits of multi-model detection while maintaining the strict low-latency requirements (under 20ms) of modern microservice gateways. Furthermore, its automated calibration phase ensures universal compatibility across different backend technologies.
