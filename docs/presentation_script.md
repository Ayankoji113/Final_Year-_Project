# MicroAPI Guard - Presentation Script (Live Demo Guide)

You can follow this step-by-step guide for your presentation and live demo.

## Step 1: PPT Presentation (5-7 mins)
Start with your PPT (`PPT/MicroAPI Guard — AI-Based Anomaly Detection System for API Traffic.pptx`).
- **Problem Statement:** Explain why API security is crucial in Microservices and why traditional rule-based systems often fail.
- **Proposed Solution:** Explain that your "MicroAPI Guard" uses AI to detect anomalies (like DDoS, SQL Injection, abnormal behavior) in API traffic.
- **Architecture:** Explain that it consists of a FastAPI Gateway, a Backend, and Redis, which is used for the Sliding Window rate-limiting logic.

## Step 2: Project Setup (Live Demo - Part 1)
Open a terminal, navigate to the `src` folder, and run your project:
```bash
cd src
docker-compose up --build
```
**Explanation to Evaluator:** "Sir/Ma'am, we have containerized the entire system using Docker. The API Gateway is running on port 5000 and the Backend microservices are on port 8000. Redis is running in the background to maintain state."

## Step 3: Normal Traffic Demo (Live Demo - Part 2)
Open a new Terminal tab (PowerShell) or use **Postman** to show normal API requests:

1. **Get Products:**
```powershell
curl.exe http://localhost:5000/api/products
```
2. **Get Single Product:**
```powershell
curl.exe http://localhost:5000/api/products/1
```
3. **Login Request:**
```powershell
curl.exe -X POST http://localhost:5000/api/users/login -H "Content-Type: application/json" -d "{\`"username\`":\`"admin\`",\`"password\`":\`"pass123\`"}"
```
4. **Get User Profile:**
```powershell
curl.exe http://localhost:5000/api/users/profile
```
5. **Place an Order:**
```powershell
curl.exe -X POST http://localhost:5000/api/orders -H "Content-Type: application/json" -d "{\`"product_id\`": 1, \`"quantity\`": 2}"
```

**Explanation to Evaluator:** "This represents normal API traffic. The Gateway intercepts these requests, forwards them to the backend, and returns the response. Simultaneously, the Gateway extracts 7 key features from each request (such as payload size, request duration, and sliding window count)."

## Step 4: Anomalous Traffic Demo (Live Demo - Part 3)
Now, simulate anomalous traffic (like sending multiple rapid requests to simulate a DDoS or Brute Force attack). Run this in PowerShell:

**1. DDoS Simulation (Rapid GET requests):**
```powershell
1..20 | ForEach-Object { curl.exe -s http://localhost:5000/api/products > $null }
```

**2. Brute Force Login Simulation (Rapid POST requests with wrong passwords):**
```powershell
1..15 | ForEach-Object { curl.exe -X POST http://localhost:5000/api/users/login -H "Content-Type: application/json" -d "{\`"username\`":\`"admin\`",\`"password\`":\`"wrongpass\`"}" -s > $null }
```
**Explanation to Evaluator:** "Here, we sent multiple requests simultaneously. The Redis sliding window rapidly increased the request count. This serves as a strong signal for our AI model that this traffic pattern might be anomalous."

## Step 5: Feature Extraction & Data Logging (Live Demo - Part 4)
Show the Gateway console logs where the requests are being printed.
Then, explain how the data is being collected for the Machine Learning model:

```bash
# Execute this to show the JSONL file inside the gateway container
docker exec -it microapi-gateway cat api_traffic_features.jsonl
```
**Explanation to Evaluator:** "The Gateway logs the extracted features of every single request into `api_traffic_features.jsonl`. This dataset contains details like request duration, body size, and the sliding window rate limit count. Our future ML Model will be trained on this exact dataset to detect and block anomalous behavior automatically."

## Step 6: Future Scope & Conclusion
- **Conclusion:** Conclude by showing that your API Gateway successfully performs data collection and routing flawlessly with very low latency.
- **Future Scope:** Explain that in the next phase, you will train an AI model (like Isolation Forest or an Autoencoder) on this extracted data and integrate it back into the Gateway to block malicious requests in real-time.
