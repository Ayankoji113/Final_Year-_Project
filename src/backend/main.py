"""
MicroAPI Guard - Mock Backend Microservices
User Service + Product Service + Order Service
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from datetime import datetime
import uuid

app = FastAPI(title="MicroAPI Guard - Backend Services", version="1.0.0")


# ======================== DUMMY DATA ========================

USERS_DB = {
    "admin": {"password": "pass123", "name": "Admin User", "email": "admin@example.com"},
    "john": {"password": "john456", "name": "John Doe", "email": "john@example.com"},
    "jane": {"password": "jane789", "name": "Jane Smith", "email": "jane@example.com"},
}

PRODUCTS_DB = [
    {"id": 1, "name": "Laptop", "price": 59999.00, "category": "Electronics", "stock": 25},
    {"id": 2, "name": "Headphones", "price": 2999.00, "category": "Electronics", "stock": 100},
    {"id": 3, "name": "Backpack", "price": 1499.00, "category": "Accessories", "stock": 50},
    {"id": 4, "name": "Mouse", "price": 799.00, "category": "Electronics", "stock": 200},
    {"id": 5, "name": "Keyboard", "price": 1299.00, "category": "Electronics", "stock": 150},
]

ORDERS_DB = []


# ======================== REQUEST MODELS ========================

class LoginRequest(BaseModel):
    username: str
    password: str

class RegisterRequest(BaseModel):
    username: str
    password: str
    name: str
    email: str

class ProductRequest(BaseModel):
    name: str
    price: float
    category: str
    stock: int = 0

class OrderRequest(BaseModel):
    product_id: int
    quantity: int


# ======================== USER SERVICE ========================

@app.post("/api/users/login")
async def login(req: LoginRequest):
    user = USERS_DB.get(req.username)
    if not user or user["password"] != req.password:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    
    token = str(uuid.uuid4())
    return {
        "status": "success",
        "message": f"Welcome back, {user['name']}!",
        "token": token,
        "user": {"username": req.username, "name": user["name"], "email": user["email"]}
    }


@app.post("/api/users/register")
async def register(req: RegisterRequest):
    if req.username in USERS_DB:
        raise HTTPException(status_code=409, detail="Username already exists")
    
    USERS_DB[req.username] = {
        "password": req.password,
        "name": req.name,
        "email": req.email
    }
    return {
        "status": "success",
        "message": f"User {req.username} registered successfully"
    }


@app.get("/api/users/profile")
async def get_profile():
    return {
        "username": "admin",
        "name": "Admin User",
        "email": "admin@example.com",
        "role": "administrator",
        "joined": "2024-01-15"
    }


# ======================== PRODUCT SERVICE ========================

@app.get("/api/products")
async def list_products():
    return {"status": "success", "count": len(PRODUCTS_DB), "products": PRODUCTS_DB}


@app.get("/api/products/{product_id}")
async def get_product(product_id: int):
    for product in PRODUCTS_DB:
        if product["id"] == product_id:
            return {"status": "success", "product": product}
    raise HTTPException(status_code=404, detail="Product not found")


@app.post("/api/products")
async def add_product(req: ProductRequest):
    new_id = max(p["id"] for p in PRODUCTS_DB) + 1
    new_product = {
        "id": new_id,
        "name": req.name,
        "price": req.price,
        "category": req.category,
        "stock": req.stock
    }
    PRODUCTS_DB.append(new_product)
    return {"status": "success", "message": "Product added", "product": new_product}


# ======================== ORDER SERVICE ========================

@app.post("/api/orders")
async def place_order(req: OrderRequest):
    product = None
    for p in PRODUCTS_DB:
        if p["id"] == req.product_id:
            product = p
            break
    
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    
    if product["stock"] < req.quantity:
        raise HTTPException(status_code=400, detail="Insufficient stock")
    
    order = {
        "order_id": str(uuid.uuid4())[:8],
        "product": product["name"],
        "quantity": req.quantity,
        "total_price": product["price"] * req.quantity,
        "status": "confirmed",
        "created_at": datetime.now().isoformat()
    }
    ORDERS_DB.append(order)
    product["stock"] -= req.quantity
    
    return {"status": "success", "message": "Order placed successfully", "order": order}


@app.get("/api/orders")
async def list_orders():
    return {"status": "success", "count": len(ORDERS_DB), "orders": ORDERS_DB}


@app.get("/api/orders/{order_id}")
async def get_order(order_id: str):
    for order in ORDERS_DB:
        if order["order_id"] == order_id:
            return {"status": "success", "order": order}
    raise HTTPException(status_code=404, detail="Order not found")


# ======================== HEALTH CHECK ========================

@app.get("/health")
async def health():
    return {"status": "healthy", "service": "backend-microservices", "timestamp": datetime.now().isoformat()}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
