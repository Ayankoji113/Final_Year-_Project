# API Documentation

## Overview
MicroAPI Guard intercepts API requests sent to the Gateway (Port `5000`) and forwards them to the backend microservices (Port `8000`).

**Base URL (Public):** `http://localhost:5000`
**Base URL (Internal Backend):** `http://backend:8000`

---

## 1. User Service Endpoints

### 1.1 User Registration
*   **Endpoint:** `/api/users/register`
*   **Method:** `POST`
*   **Content-Type:** `application/json`
*   **Payload:**
    ```json
    {
      "username": "johndoe",
      "password": "password123",
      "name": "John Doe",
      "email": "john@example.com"
    }
    ```
*   **Response (200 OK):**
    ```json
    {
      "status": "success",
      "message": "User johndoe registered successfully"
    }
    ```

### 1.2 User Login
*   **Endpoint:** `/api/users/login`
*   **Method:** `POST`
*   **Content-Type:** `application/json`
*   **Payload:**
    ```json
    {
      "username": "admin",
      "password": "pass123"
    }
    ```
*   **Response (200 OK):** Returns an auth token.
*   **Response (401 Unauthorized):** Invalid credentials.

---

## 2. Product Service Endpoints

### 2.1 Get All Products
*   **Endpoint:** `/api/products`
*   **Method:** `GET`
*   **Response (200 OK):**
    ```json
    {
      "status": "success",
      "count": 5,
      "products": [
        {"id": 1, "name": "Laptop", "price": 59999.0, "category": "Electronics", "stock": 25}
      ]
    }
    ```

---

## 3. Order Service Endpoints

### 3.1 Place an Order
*   **Endpoint:** `/api/orders`
*   **Method:** `POST`
*   **Content-Type:** `application/json`
*   **Payload:**
    ```json
    {
      "product_id": 1,
      "quantity": 2
    }
    ```
*   **Response (200 OK):**
    ```json
    {
      "status": "success",
      "message": "Order placed successfully",
      "order": {
        "order_id": "df831774",
        "total_price": 119998.0
      }
    }
    ```
*   **Response (400 Bad Request):** Insufficient stock.

---

## 4. Gateway Security Responses
If the ML Inference Engine classifies a request as malicious, the Gateway intercepts it and returns:

*   **Status Code:** `403 Forbidden`
*   **Response:**
    ```json
    {
      "detail": "Request blocked by MicroAPI Guard Security Policies."
    }
    ```
