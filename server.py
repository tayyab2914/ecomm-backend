from fastapi import FastAPI, APIRouter, HTTPException, Depends, UploadFile, File, Query, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.staticfiles import StaticFiles
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, EmailStr, ConfigDict
from typing import List, Optional, Any
import uuid
from datetime import datetime, timezone, timedelta
import jwt
import bcrypt
import asyncio
import resend
import aiofiles
import secrets
import re
import cloudinary
import cloudinary.uploader

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# JWT Config
JWT_SECRET = os.environ.get('JWT_SECRET', 'default_secret')
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24

# Resend Config
resend.api_key = os.environ.get('RESEND_API_KEY', '')
SENDER_EMAIL = os.environ.get('SENDER_EMAIL', 'onboarding@resend.dev')

# Cloudinary Config
cloudinary.config(
    cloud_name=os.environ.get('CLOUDINARY_CLOUD_NAME'),
    api_key=os.environ.get('CLOUDINARY_API_KEY'),
    api_secret=os.environ.get('CLOUDINARY_API_SECRET'),
    secure=True
)

app = FastAPI(title="E-Commerce MVP API")
api_router = APIRouter(prefix="/api")
security = HTTPBearer(auto_error=False)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ============ PYDANTIC MODELS ============

class UserCreate(BaseModel):
    name: str
    email: EmailStr
    password: str
    phone: Optional[str] = None

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserResponse(BaseModel):
    id: str
    name: str
    email: str
    phone: Optional[str] = None
    role: str
    is_active: bool
    created_at: str

class UserUpdate(BaseModel):
    name: Optional[str] = None
    phone: Optional[str] = None
    default_address: Optional[dict] = None

class PasswordReset(BaseModel):
    email: EmailStr

class PasswordResetConfirm(BaseModel):
    token: str
    new_password: str

class CategoryCreate(BaseModel):
    name: str
    description: Optional[str] = None

class CategoryResponse(BaseModel):
    id: str
    name: str
    slug: str
    description: Optional[str] = None
    is_active: bool

class ProductCreate(BaseModel):
    name: str
    description: str
    price: float
    category_id: str
    stock_quantity: int = 0
    sku: Optional[str] = None
    status: str = "active"
    images: List[str] = []

class ProductUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    price: Optional[float] = None
    category_id: Optional[str] = None
    stock_quantity: Optional[int] = None
    sku: Optional[str] = None
    status: Optional[str] = None
    images: Optional[List[str]] = None

class ProductResponse(BaseModel):
    id: str
    name: str
    description: str
    price: float
    category_id: str
    category_name: Optional[str] = None
    stock_quantity: int
    images: List[str]
    sku: Optional[str] = None
    status: str
    created_at: str

class CartItemAdd(BaseModel):
    product_id: str
    quantity: int = 1

class CartItemUpdate(BaseModel):
    quantity: int

class CartItemResponse(BaseModel):
    id: str
    product_id: str
    product_name: str
    product_price: float
    product_image: Optional[str] = None
    quantity: int
    line_total: float
    stock_quantity: int

class AddressSchema(BaseModel):
    street: str
    city: str
    state: str
    zip_code: str
    country: str

class CheckoutCreate(BaseModel):
    customer_name: str
    customer_email: EmailStr
    customer_phone: str
    shipping_address: AddressSchema

class OrderItemResponse(BaseModel):
    product_id: str
    product_name: str
    product_price: float
    quantity: int
    line_total: float

class OrderResponse(BaseModel):
    id: str
    order_number: str
    user_id: Optional[str] = None
    status: str
    total_amount: float
    customer_name: str
    customer_email: str
    customer_phone: str
    shipping_address: dict
    items: List[OrderItemResponse]
    notes: Optional[str] = None
    created_at: str
    updated_at: str

class OrderStatusUpdate(BaseModel):
    status: str
    notes: Optional[str] = None

class AdminUserCreate(BaseModel):
    name: str
    email: EmailStr
    password: str
    role: str = "staff"

class AdminUserUpdate(BaseModel):
    name: Optional[str] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None

# ============ HELPER FUNCTIONS ============

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def create_token(user_id: str, role: str) -> str:
    payload = {
        "user_id": user_id,
        "role": role,
        "exp": datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRATION_HOURS)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if not credentials:
        raise HTTPException(status_code=401, detail="Not authenticated")
    payload = decode_token(credentials.credentials)
    user = await db.users.find_one({"id": payload["user_id"]}, {"_id": 0})
    if not user or not user.get("is_active"):
        raise HTTPException(status_code=401, detail="User not found or inactive")
    return user

async def get_optional_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if not credentials:
        return None
    try:
        payload = decode_token(credentials.credentials)
        user = await db.users.find_one({"id": payload["user_id"]}, {"_id": 0})
        return user if user and user.get("is_active") else None
    except:
        return None

async def get_admin_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    user = await get_current_user(credentials)
    if user["role"] not in ["admin", "super_admin"]:
        raise HTTPException(status_code=403, detail="Admin access required")
    return user

async def get_super_admin(credentials: HTTPAuthorizationCredentials = Depends(security)):
    user = await get_current_user(credentials)
    if user["role"] != "super_admin":
        raise HTTPException(status_code=403, detail="Super admin access required")
    return user

def slugify(text: str) -> str:
    text = text.lower().strip()
    text = re.sub(r'[^\w\s-]', '', text)
    text = re.sub(r'[\s_-]+', '-', text)
    return text

def generate_order_number() -> str:
    date_part = datetime.now(timezone.utc).strftime("%Y%m%d")
    random_part = secrets.token_hex(3).upper()
    return f"ORD-{date_part}-{random_part}"

async def send_email(to: str, subject: str, html: str):
    if not resend.api_key:
        logger.warning("Resend API key not configured, skipping email")
        return None
    try:
        params = {
            "from": SENDER_EMAIL,
            "to": [to],
            "subject": subject,
            "html": html
        }
        result = await asyncio.to_thread(resend.Emails.send, params)
        logger.info(f"Email sent to {to}: {result}")
        return result
    except Exception as e:
        logger.error(f"Failed to send email to {to}: {e}")
        return None

# ============ AUTH ROUTES ============

@api_router.post("/auth/register", response_model=dict)
async def register(user: UserCreate):
    existing = await db.users.find_one({"email": user.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    user_doc = {
        "id": str(uuid.uuid4()),
        "name": user.name,
        "email": user.email,
        "password_hash": hash_password(user.password),
        "phone": user.phone,
        "role": "customer",
        "default_address": None,
        "is_active": True,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": datetime.now(timezone.utc).isoformat()
    }
    await db.users.insert_one(user_doc)
    token = create_token(user_doc["id"], user_doc["role"])
    
    # Send welcome email
    await send_email(
        user.email,
        "Welcome to Our Store!",
        f"<h1>Welcome, {user.name}!</h1><p>Thank you for creating an account with us.</p>"
    )
    
    return {
        "token": token,
        "user": {
            "id": user_doc["id"],
            "name": user_doc["name"],
            "email": user_doc["email"],
            "role": user_doc["role"]
        }
    }

@api_router.post("/auth/login", response_model=dict)
async def login(credentials: UserLogin):
    user = await db.users.find_one({"email": credentials.email}, {"_id": 0})
    if not user or not verify_password(credentials.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if not user.get("is_active"):
        raise HTTPException(status_code=401, detail="Account is deactivated")
    
    token = create_token(user["id"], user["role"])
    return {
        "token": token,
        "user": {
            "id": user["id"],
            "name": user["name"],
            "email": user["email"],
            "role": user["role"]
        }
    }

@api_router.get("/auth/me", response_model=UserResponse)
async def get_me(user: dict = Depends(get_current_user)):
    return UserResponse(
        id=user["id"],
        name=user["name"],
        email=user["email"],
        phone=user.get("phone"),
        role=user["role"],
        is_active=user["is_active"],
        created_at=user["created_at"]
    )

@api_router.put("/auth/profile", response_model=UserResponse)
async def update_profile(update: UserUpdate, user: dict = Depends(get_current_user)):
    update_data = {k: v for k, v in update.model_dump().items() if v is not None}
    update_data["updated_at"] = datetime.now(timezone.utc).isoformat()
    
    await db.users.update_one({"id": user["id"]}, {"$set": update_data})
    updated_user = await db.users.find_one({"id": user["id"]}, {"_id": 0})
    
    return UserResponse(
        id=updated_user["id"],
        name=updated_user["name"],
        email=updated_user["email"],
        phone=updated_user.get("phone"),
        role=updated_user["role"],
        is_active=updated_user["is_active"],
        created_at=updated_user["created_at"]
    )

@api_router.post("/auth/password-reset", response_model=dict)
async def request_password_reset(data: PasswordReset):
    user = await db.users.find_one({"email": data.email}, {"_id": 0})
    if not user:
        return {"message": "If the email exists, a reset link will be sent"}
    
    reset_token = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
    
    await db.password_resets.insert_one({
        "id": str(uuid.uuid4()),
        "user_id": user["id"],
        "token": reset_token,
        "expires_at": expires_at.isoformat(),
        "used": False
    })
    
    await send_email(
        user["email"],
        "Password Reset Request",
        f"<h1>Password Reset</h1><p>Use this token to reset your password: <strong>{reset_token}</strong></p><p>This token expires in 1 hour.</p>"
    )
    
    return {"message": "If the email exists, a reset link will be sent"}

@api_router.post("/auth/password-reset/confirm", response_model=dict)
async def confirm_password_reset(data: PasswordResetConfirm):
    reset_doc = await db.password_resets.find_one({"token": data.token, "used": False}, {"_id": 0})
    if not reset_doc:
        raise HTTPException(status_code=400, detail="Invalid or expired token")
    
    if datetime.fromisoformat(reset_doc["expires_at"]) < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="Token has expired")
    
    await db.users.update_one(
        {"id": reset_doc["user_id"]},
        {"$set": {"password_hash": hash_password(data.new_password), "updated_at": datetime.now(timezone.utc).isoformat()}}
    )
    await db.password_resets.update_one({"token": data.token}, {"$set": {"used": True}})
    
    return {"message": "Password reset successful"}

# ============ CATEGORY ROUTES ============

@api_router.get("/categories", response_model=List[CategoryResponse])
async def get_categories():
    categories = await db.categories.find({"is_active": True}, {"_id": 0}).to_list(100)
    return [CategoryResponse(**cat) for cat in categories]

@api_router.get("/categories/{category_id}", response_model=CategoryResponse)
async def get_category(category_id: str):
    category = await db.categories.find_one({"id": category_id}, {"_id": 0})
    if not category:
        raise HTTPException(status_code=404, detail="Category not found")
    return CategoryResponse(**category)

@api_router.post("/admin/categories", response_model=CategoryResponse)
async def create_category(category: CategoryCreate, admin: dict = Depends(get_admin_user)):
    slug = slugify(category.name)
    existing = await db.categories.find_one({"slug": slug})
    if existing:
        raise HTTPException(status_code=400, detail="Category with this name already exists")
    
    cat_doc = {
        "id": str(uuid.uuid4()),
        "name": category.name,
        "slug": slug,
        "description": category.description,
        "is_active": True
    }
    await db.categories.insert_one(cat_doc)
    return CategoryResponse(**cat_doc)

@api_router.put("/admin/categories/{category_id}", response_model=CategoryResponse)
async def update_category(category_id: str, update: CategoryCreate, admin: dict = Depends(get_admin_user)):
    category = await db.categories.find_one({"id": category_id}, {"_id": 0})
    if not category:
        raise HTTPException(status_code=404, detail="Category not found")
    
    slug = slugify(update.name)
    cat_doc = {
        "name": update.name,
        "slug": slug,
        "description": update.description
    }
    await db.categories.update_one({"id": category_id}, {"$set": cat_doc})
    updated = await db.categories.find_one({"id": category_id}, {"_id": 0})
    return CategoryResponse(**updated)

@api_router.delete("/admin/categories/{category_id}")
async def delete_category(category_id: str, admin: dict = Depends(get_admin_user)):
    result = await db.categories.update_one({"id": category_id}, {"$set": {"is_active": False}})
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Category not found")
    return {"message": "Category deleted"}

# ============ PRODUCT ROUTES ============

@api_router.get("/products", response_model=dict)
async def get_products(
    search: Optional[str] = None,
    category_id: Optional[str] = None,
    sort: Optional[str] = "newest",
    page: int = Query(1, ge=1),
    limit: int = Query(12, ge=1, le=48)
):
    query = {"status": "active"}
    
    if search:
        query["$or"] = [
            {"name": {"$regex": search, "$options": "i"}},
            {"description": {"$regex": search, "$options": "i"}}
        ]
    
    if category_id:
        query["category_id"] = category_id
    
    sort_options = {
        "newest": [("created_at", -1)],
        "price_low": [("price", 1)],
        "price_high": [("price", -1)],
        "name_az": [("name", 1)]
    }
    sort_key = sort_options.get(sort, [("created_at", -1)])
    
    total = await db.products.count_documents(query)
    skip = (page - 1) * limit
    
    products = await db.products.find(query, {"_id": 0}).sort(sort_key).skip(skip).limit(limit).to_list(limit)
    
    # Get category names
    category_ids = list(set(p["category_id"] for p in products))
    categories = await db.categories.find({"id": {"$in": category_ids}}, {"_id": 0}).to_list(100)
    cat_map = {c["id"]: c["name"] for c in categories}
    
    for p in products:
        p["category_name"] = cat_map.get(p["category_id"], "")
    
    return {
        "products": [ProductResponse(**p) for p in products],
        "total": total,
        "page": page,
        "pages": (total + limit - 1) // limit
    }

@api_router.get("/products/{product_id}", response_model=ProductResponse)
async def get_product(product_id: str):
    product = await db.products.find_one({"id": product_id}, {"_id": 0})
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    
    category = await db.categories.find_one({"id": product["category_id"]}, {"_id": 0})
    product["category_name"] = category["name"] if category else ""
    
    return ProductResponse(**product)

@api_router.get("/admin/products", response_model=dict)
async def get_admin_products(
    search: Optional[str] = None,
    status: Optional[str] = None,
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    admin: dict = Depends(get_admin_user)
):
    query = {}
    if search:
        query["$or"] = [
            {"name": {"$regex": search, "$options": "i"}},
            {"sku": {"$regex": search, "$options": "i"}}
        ]
    if status:
        query["status"] = status
    
    total = await db.products.count_documents(query)
    skip = (page - 1) * limit
    
    products = await db.products.find(query, {"_id": 0}).sort("created_at", -1).skip(skip).limit(limit).to_list(limit)
    
    category_ids = list(set(p["category_id"] for p in products))
    categories = await db.categories.find({"id": {"$in": category_ids}}, {"_id": 0}).to_list(100)
    cat_map = {c["id"]: c["name"] for c in categories}
    
    for p in products:
        p["category_name"] = cat_map.get(p["category_id"], "")
    
    return {
        "products": [ProductResponse(**p) for p in products],
        "total": total,
        "page": page,
        "pages": (total + limit - 1) // limit
    }

@api_router.post("/admin/products", response_model=ProductResponse)
async def create_product(product: ProductCreate, admin: dict = Depends(get_admin_user)):
    if product.price < 0:
        raise HTTPException(status_code=400, detail="Price cannot be negative")
    if product.stock_quantity < 0:
        raise HTTPException(status_code=400, detail="Stock quantity cannot be negative")
    
    category = await db.categories.find_one({"id": product.category_id}, {"_id": 0})
    if not category:
        raise HTTPException(status_code=400, detail="Invalid category")
    
    product_doc = {
        "id": str(uuid.uuid4()),
        "name": product.name,
        "description": product.description,
        "price": product.price,
        "category_id": product.category_id,
        "stock_quantity": product.stock_quantity,
        "images": product.images,
        "sku": product.sku or f"SKU-{secrets.token_hex(4).upper()}",
        "status": product.status,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": datetime.now(timezone.utc).isoformat()
    }
    await db.products.insert_one(product_doc)
    product_doc["category_name"] = category["name"]
    return ProductResponse(**product_doc)

@api_router.put("/admin/products/{product_id}", response_model=ProductResponse)
async def update_product(product_id: str, update: ProductUpdate, admin: dict = Depends(get_admin_user)):
    product = await db.products.find_one({"id": product_id}, {"_id": 0})
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    
    update_data = {k: v for k, v in update.model_dump().items() if v is not None}
    
    if "price" in update_data and update_data["price"] < 0:
        raise HTTPException(status_code=400, detail="Price cannot be negative")
    if "stock_quantity" in update_data and update_data["stock_quantity"] < 0:
        raise HTTPException(status_code=400, detail="Stock quantity cannot be negative")
    if "category_id" in update_data:
        category = await db.categories.find_one({"id": update_data["category_id"]}, {"_id": 0})
        if not category:
            raise HTTPException(status_code=400, detail="Invalid category")
    
    update_data["updated_at"] = datetime.now(timezone.utc).isoformat()
    await db.products.update_one({"id": product_id}, {"$set": update_data})
    
    updated = await db.products.find_one({"id": product_id}, {"_id": 0})
    category = await db.categories.find_one({"id": updated["category_id"]}, {"_id": 0})
    updated["category_name"] = category["name"] if category else ""
    
    return ProductResponse(**updated)

@api_router.delete("/admin/products/{product_id}")
async def delete_product(product_id: str, admin: dict = Depends(get_admin_user)):
    result = await db.products.update_one({"id": product_id}, {"$set": {"status": "inactive"}})
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Product not found")
    return {"message": "Product deleted"}

@api_router.post("/admin/upload-image")
async def upload_image(file: UploadFile = File(...), admin: dict = Depends(get_admin_user)):
    if not file.content_type or not file.content_type.startswith("image/"):
        raise HTTPException(status_code=400, detail="File must be an image")
    
    content = await file.read()
    if len(content) > 10 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="Image must be less than 10MB")
    
    try:
        result = await asyncio.to_thread(
            cloudinary.uploader.upload,
            content,
            folder="products",
            resource_type="image"
        )
        return {"url": result["secure_url"]}
    except Exception as e:
        logger.error(f"Cloudinary upload failed: {e}")
        raise HTTPException(status_code=500, detail="Image upload failed")

# ============ CART ROUTES ============

@api_router.get("/cart", response_model=dict)
async def get_cart(user: dict = Depends(get_optional_user), session_id: Optional[str] = None):
    query = {"user_id": user["id"]} if user else {"session_id": session_id}
    if not query.get("user_id") and not query.get("session_id"):
        return {"items": [], "subtotal": 0, "total": 0}
    
    cart_items = await db.cart.find(query, {"_id": 0}).to_list(100)
    
    items = []
    subtotal = 0
    
    for item in cart_items:
        product = await db.products.find_one({"id": item["product_id"], "status": "active"}, {"_id": 0})
        if product:
            line_total = product["price"] * item["quantity"]
            items.append(CartItemResponse(
                id=item["id"],
                product_id=product["id"],
                product_name=product["name"],
                product_price=product["price"],
                product_image=product["images"][0] if product["images"] else None,
                quantity=item["quantity"],
                line_total=line_total,
                stock_quantity=product["stock_quantity"]
            ))
            subtotal += line_total
    
    return {"items": items, "subtotal": subtotal, "total": subtotal}

@api_router.post("/cart", response_model=dict)
async def add_to_cart(
    item: CartItemAdd,
    user: dict = Depends(get_optional_user),
    session_id: Optional[str] = None
):
    product = await db.products.find_one({"id": item.product_id, "status": "active"}, {"_id": 0})
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    
    if product["stock_quantity"] < item.quantity:
        raise HTTPException(status_code=400, detail="Not enough stock available")
    
    query = {"user_id": user["id"], "product_id": item.product_id} if user else {"session_id": session_id, "product_id": item.product_id}
    
    if not user and not session_id:
        session_id = str(uuid.uuid4())
        query = {"session_id": session_id, "product_id": item.product_id}
    
    existing = await db.cart.find_one(query, {"_id": 0})
    
    if existing:
        new_qty = existing["quantity"] + item.quantity
        if new_qty > product["stock_quantity"]:
            raise HTTPException(status_code=400, detail="Not enough stock available")
        await db.cart.update_one({"id": existing["id"]}, {"$set": {"quantity": new_qty}})
    else:
        cart_doc = {
            "id": str(uuid.uuid4()),
            "user_id": user["id"] if user else None,
            "session_id": session_id if not user else None,
            "product_id": item.product_id,
            "quantity": item.quantity,
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        await db.cart.insert_one(cart_doc)
    
    return {"message": "Item added to cart", "session_id": session_id if not user else None}

@api_router.put("/cart/{item_id}", response_model=dict)
async def update_cart_item(
    item_id: str,
    update: CartItemUpdate,
    user: dict = Depends(get_optional_user),
    session_id: Optional[str] = None
):
    query = {"id": item_id}
    if user:
        query["user_id"] = user["id"]
    elif session_id:
        query["session_id"] = session_id
    else:
        raise HTTPException(status_code=400, detail="Session ID required")
    
    cart_item = await db.cart.find_one(query, {"_id": 0})
    if not cart_item:
        raise HTTPException(status_code=404, detail="Cart item not found")
    
    if update.quantity <= 0:
        await db.cart.delete_one({"id": item_id})
        return {"message": "Item removed from cart"}
    
    product = await db.products.find_one({"id": cart_item["product_id"]}, {"_id": 0})
    if update.quantity > product["stock_quantity"]:
        raise HTTPException(status_code=400, detail="Not enough stock available")
    
    await db.cart.update_one({"id": item_id}, {"$set": {"quantity": update.quantity}})
    return {"message": "Cart updated"}

@api_router.delete("/cart/{item_id}")
async def remove_from_cart(
    item_id: str,
    user: dict = Depends(get_optional_user),
    session_id: Optional[str] = None
):
    query = {"id": item_id}
    if user:
        query["user_id"] = user["id"]
    elif session_id:
        query["session_id"] = session_id
    else:
        raise HTTPException(status_code=400, detail="Session ID required")
    
    result = await db.cart.delete_one(query)
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Cart item not found")
    return {"message": "Item removed from cart"}

@api_router.delete("/cart")
async def clear_cart(user: dict = Depends(get_optional_user), session_id: Optional[str] = None):
    query = {"user_id": user["id"]} if user else {"session_id": session_id}
    if query:
        await db.cart.delete_many(query)
    return {"message": "Cart cleared"}

# ============ ORDER ROUTES ============

@api_router.post("/orders", response_model=OrderResponse)
async def create_order(
    checkout: CheckoutCreate,
    user: dict = Depends(get_optional_user),
    session_id: Optional[str] = None
):
    query = {"user_id": user["id"]} if user else {"session_id": session_id}
    if not query.get("user_id") and not query.get("session_id"):
        raise HTTPException(status_code=400, detail="Cart is empty")
    
    cart_items = await db.cart.find(query, {"_id": 0}).to_list(100)
    if not cart_items:
        raise HTTPException(status_code=400, detail="Cart is empty")
    
    order_items = []
    total_amount = 0
    
    for item in cart_items:
        product = await db.products.find_one({"id": item["product_id"], "status": "active"}, {"_id": 0})
        if not product:
            raise HTTPException(status_code=400, detail=f"Product {item['product_id']} not found")
        if product["stock_quantity"] < item["quantity"]:
            raise HTTPException(status_code=400, detail=f"Not enough stock for {product['name']}")
        
        line_total = product["price"] * item["quantity"]
        order_items.append({
            "product_id": product["id"],
            "product_name": product["name"],
            "product_price": product["price"],
            "quantity": item["quantity"],
            "line_total": line_total
        })
        total_amount += line_total
        
        # Reduce stock
        await db.products.update_one(
            {"id": product["id"]},
            {"$inc": {"stock_quantity": -item["quantity"]}}
        )
    
    order_doc = {
        "id": str(uuid.uuid4()),
        "order_number": generate_order_number(),
        "user_id": user["id"] if user else None,
        "status": "pending",
        "total_amount": total_amount,
        "customer_name": checkout.customer_name,
        "customer_email": checkout.customer_email,
        "customer_phone": checkout.customer_phone,
        "shipping_address": checkout.shipping_address.model_dump(),
        "items": order_items,
        "notes": None,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": datetime.now(timezone.utc).isoformat()
    }
    
    await db.orders.insert_one(order_doc)
    await db.cart.delete_many(query)
    
    # Send order confirmation email
    items_html = "".join([f"<tr><td>{i['product_name']}</td><td>{i['quantity']}</td><td>${i['line_total']:.2f}</td></tr>" for i in order_items])
    await send_email(
        checkout.customer_email,
        f"Order Confirmation - {order_doc['order_number']}",
        f"""
        <h1>Thank you for your order!</h1>
        <p>Order Number: <strong>{order_doc['order_number']}</strong></p>
        <h3>Items Ordered:</h3>
        <table border="1" cellpadding="5"><tr><th>Product</th><th>Qty</th><th>Total</th></tr>{items_html}</table>
        <p><strong>Total: ${total_amount:.2f}</strong></p>
        <h3>Shipping Address:</h3>
        <p>{checkout.shipping_address.street}<br>{checkout.shipping_address.city}, {checkout.shipping_address.state} {checkout.shipping_address.zip_code}<br>{checkout.shipping_address.country}</p>
        <p>We'll notify you when your order ships. Payment is due on delivery.</p>
        """
    )

    # Send notification email to all admins
    admins = await db.users.find(
        {"role": {"$in": ["admin", "super_admin"]}, "is_active": True},
        {"_id": 0, "email": 1}
    ).to_list(100)
    admin_notification_html = f"""
        <h1>New Order Placed</h1>
        <p>A new order has been placed and requires your attention.</p>
        <p><strong>Order Number:</strong> {order_doc['order_number']}</p>
        <p><strong>Customer:</strong> {checkout.customer_name} ({checkout.customer_email})</p>
        <p><strong>Phone:</strong> {checkout.customer_phone}</p>
        <h3>Items Ordered:</h3>
        <table border="1" cellpadding="5"><tr><th>Product</th><th>Qty</th><th>Total</th></tr>{items_html}</table>
        <p><strong>Order Total: ${total_amount:.2f}</strong></p>
        <h3>Shipping Address:</h3>
        <p>{checkout.shipping_address.street}<br>{checkout.shipping_address.city}, {checkout.shipping_address.state} {checkout.shipping_address.zip_code}<br>{checkout.shipping_address.country}</p>
        <p>Please log in to the admin panel to process this order.</p>
    """
    for admin in admins:
        await send_email(
            admin["email"],
            f"New Order Received - {order_doc['order_number']}",
            admin_notification_html
        )

    return OrderResponse(**order_doc)

@api_router.get("/orders", response_model=List[OrderResponse])
async def get_my_orders(user: dict = Depends(get_current_user)):
    orders = await db.orders.find({"user_id": user["id"]}, {"_id": 0}).sort("created_at", -1).to_list(100)
    return [OrderResponse(**o) for o in orders]

@api_router.get("/orders/{order_id}", response_model=OrderResponse)
async def get_order(order_id: str, user: dict = Depends(get_optional_user)):
    order = await db.orders.find_one({"id": order_id}, {"_id": 0})
    if not order:
        order = await db.orders.find_one({"order_number": order_id}, {"_id": 0})
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    
    # Check authorization
    if user:
        if user["role"] not in ["admin", "super_admin"] and order.get("user_id") != user["id"]:
            raise HTTPException(status_code=403, detail="Access denied")
    
    return OrderResponse(**order)

@api_router.get("/orders/track/{order_number}", response_model=OrderResponse)
async def track_order(order_number: str):
    order = await db.orders.find_one({"order_number": order_number}, {"_id": 0})
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    return OrderResponse(**order)

# ============ ADMIN ORDER ROUTES ============

@api_router.get("/admin/orders", response_model=dict)
async def get_admin_orders(
    status: Optional[str] = None,
    search: Optional[str] = None,
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    admin: dict = Depends(get_admin_user)
):
    query = {}
    if status:
        query["status"] = status
    if search:
        query["$or"] = [
            {"order_number": {"$regex": search, "$options": "i"}},
            {"customer_name": {"$regex": search, "$options": "i"}},
            {"customer_email": {"$regex": search, "$options": "i"}}
        ]
    
    total = await db.orders.count_documents(query)
    skip = (page - 1) * limit
    
    orders = await db.orders.find(query, {"_id": 0}).sort("created_at", -1).skip(skip).limit(limit).to_list(limit)
    
    return {
        "orders": [OrderResponse(**o) for o in orders],
        "total": total,
        "page": page,
        "pages": (total + limit - 1) // limit
    }

@api_router.put("/admin/orders/{order_id}/status", response_model=OrderResponse)
async def update_order_status(order_id: str, update: OrderStatusUpdate, admin: dict = Depends(get_admin_user)):
    order = await db.orders.find_one({"id": order_id}, {"_id": 0})
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    
    valid_statuses = ["pending", "processing", "shipped", "delivered", "cancelled"]
    if update.status not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of: {valid_statuses}")
    
    update_data = {
        "status": update.status,
        "updated_at": datetime.now(timezone.utc).isoformat()
    }
    if update.notes:
        update_data["notes"] = update.notes
    
    await db.orders.update_one({"id": order_id}, {"$set": update_data})
    
    # Send status update email
    status_messages = {
        "processing": "Your order is now being processed.",
        "shipped": "Great news! Your order has been shipped.",
        "delivered": "Your order has been delivered.",
        "cancelled": "Your order has been cancelled."
    }
    
    if update.status in status_messages:
        await send_email(
            order["customer_email"],
            f"Order Update - {order['order_number']}",
            f"<h1>Order Status Update</h1><p>Order: <strong>{order['order_number']}</strong></p><p>{status_messages[update.status]}</p><p>New Status: <strong>{update.status.upper()}</strong></p>"
        )
    
    updated = await db.orders.find_one({"id": order_id}, {"_id": 0})
    return OrderResponse(**updated)

# ============ ADMIN CUSTOMER ROUTES ============

@api_router.get("/admin/customers", response_model=dict)
async def get_customers(
    search: Optional[str] = None,
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    admin: dict = Depends(get_admin_user)
):
    query = {"role": "customer"}
    if search:
        query["$or"] = [
            {"name": {"$regex": search, "$options": "i"}},
            {"email": {"$regex": search, "$options": "i"}}
        ]
    
    total = await db.users.count_documents(query)
    skip = (page - 1) * limit
    
    customers = await db.users.find(query, {"_id": 0, "password_hash": 0}).sort("created_at", -1).skip(skip).limit(limit).to_list(limit)
    
    # Get order counts for each customer
    for customer in customers:
        customer["order_count"] = await db.orders.count_documents({"user_id": customer["id"]})
    
    return {
        "customers": customers,
        "total": total,
        "page": page,
        "pages": (total + limit - 1) // limit
    }

@api_router.get("/admin/customers/{customer_id}", response_model=dict)
async def get_customer_detail(customer_id: str, admin: dict = Depends(get_admin_user)):
    customer = await db.users.find_one({"id": customer_id, "role": "customer"}, {"_id": 0, "password_hash": 0})
    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found")
    
    orders = await db.orders.find({"user_id": customer_id}, {"_id": 0}).sort("created_at", -1).to_list(100)
    
    return {
        "customer": customer,
        "orders": [OrderResponse(**o) for o in orders]
    }

@api_router.put("/admin/customers/{customer_id}/deactivate")
async def deactivate_customer(customer_id: str, admin: dict = Depends(get_admin_user)):
    result = await db.users.update_one({"id": customer_id, "role": "customer"}, {"$set": {"is_active": False}})
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Customer not found")
    return {"message": "Customer deactivated"}

# ============ ADMIN USER MANAGEMENT ============

@api_router.get("/admin/users", response_model=List[dict])
async def get_admin_users(admin: dict = Depends(get_super_admin)):
    users = await db.users.find({"role": {"$in": ["admin", "super_admin"]}}, {"_id": 0, "password_hash": 0}).to_list(100)
    return users

@api_router.post("/admin/users", response_model=dict)
async def create_admin_user(user: AdminUserCreate, admin: dict = Depends(get_super_admin)):
    existing = await db.users.find_one({"email": user.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    if user.role not in ["admin", "staff"]:
        raise HTTPException(status_code=400, detail="Invalid role. Must be 'admin' or 'staff'")
    
    user_doc = {
        "id": str(uuid.uuid4()),
        "name": user.name,
        "email": user.email,
        "password_hash": hash_password(user.password),
        "phone": None,
        "role": user.role if user.role == "admin" else "admin",  # staff mapped to admin for simplicity
        "is_active": True,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": datetime.now(timezone.utc).isoformat()
    }
    await db.users.insert_one(user_doc)
    
    return {"id": user_doc["id"], "name": user_doc["name"], "email": user_doc["email"], "role": user_doc["role"]}

@api_router.put("/admin/users/{user_id}", response_model=dict)
async def update_admin_user(user_id: str, update: AdminUserUpdate, admin: dict = Depends(get_super_admin)):
    user = await db.users.find_one({"id": user_id, "role": {"$in": ["admin", "super_admin"]}}, {"_id": 0})
    if not user:
        raise HTTPException(status_code=404, detail="Admin user not found")
    
    if user_id == admin["id"] and update.is_active == False:
        raise HTTPException(status_code=400, detail="Cannot deactivate yourself")
    
    update_data = {k: v for k, v in update.model_dump().items() if v is not None}
    update_data["updated_at"] = datetime.now(timezone.utc).isoformat()
    
    await db.users.update_one({"id": user_id}, {"$set": update_data})
    updated = await db.users.find_one({"id": user_id}, {"_id": 0, "password_hash": 0})
    
    return updated

# ============ ADMIN DASHBOARD ============

@api_router.get("/admin/dashboard", response_model=dict)
async def get_dashboard(admin: dict = Depends(get_admin_user)):
    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
    week_start = (now - timedelta(days=7)).isoformat()
    month_start = (now - timedelta(days=30)).isoformat()
    
    # Order counts
    total_orders = await db.orders.count_documents({})
    orders_today = await db.orders.count_documents({"created_at": {"$gte": today_start}})
    orders_week = await db.orders.count_documents({"created_at": {"$gte": week_start}})
    orders_month = await db.orders.count_documents({"created_at": {"$gte": month_start}})
    
    # Revenue
    pipeline = [{"$group": {"_id": None, "total": {"$sum": "$total_amount"}}}]
    total_revenue_result = await db.orders.aggregate(pipeline).to_list(1)
    total_revenue = total_revenue_result[0]["total"] if total_revenue_result else 0
    
    today_pipeline = [{"$match": {"created_at": {"$gte": today_start}}}, {"$group": {"_id": None, "total": {"$sum": "$total_amount"}}}]
    today_revenue_result = await db.orders.aggregate(today_pipeline).to_list(1)
    today_revenue = today_revenue_result[0]["total"] if today_revenue_result else 0
    
    week_pipeline = [{"$match": {"created_at": {"$gte": week_start}}}, {"$group": {"_id": None, "total": {"$sum": "$total_amount"}}}]
    week_revenue_result = await db.orders.aggregate(week_pipeline).to_list(1)
    week_revenue = week_revenue_result[0]["total"] if week_revenue_result else 0
    
    month_pipeline = [{"$match": {"created_at": {"$gte": month_start}}}, {"$group": {"_id": None, "total": {"$sum": "$total_amount"}}}]
    month_revenue_result = await db.orders.aggregate(month_pipeline).to_list(1)
    month_revenue = month_revenue_result[0]["total"] if month_revenue_result else 0
    
    # Recent orders
    recent_orders = await db.orders.find({}, {"_id": 0}).sort("created_at", -1).limit(10).to_list(10)
    
    # Low stock products (below 10)
    low_stock = await db.products.find({"stock_quantity": {"$lt": 10}, "status": "active"}, {"_id": 0}).to_list(20)
    
    # New customers this week
    new_customers_week = await db.users.count_documents({"role": "customer", "created_at": {"$gte": week_start}})
    new_customers_month = await db.users.count_documents({"role": "customer", "created_at": {"$gte": month_start}})
    
    # Pending orders count
    pending_orders = await db.orders.count_documents({"status": "pending"})
    
    return {
        "orders": {
            "total": total_orders,
            "today": orders_today,
            "week": orders_week,
            "month": orders_month,
            "pending": pending_orders
        },
        "revenue": {
            "total": total_revenue,
            "today": today_revenue,
            "week": week_revenue,
            "month": month_revenue
        },
        "recent_orders": [OrderResponse(**o) for o in recent_orders],
        "low_stock_products": low_stock,
        "new_customers": {
            "week": new_customers_week,
            "month": new_customers_month
        }
    }

# ============ SEED DATA ============

@api_router.post("/seed")
async def seed_data():
    # Check if already seeded
    existing = await db.users.find_one({"email": "admin@store.com"})
    if existing:
        return {"message": "Data already seeded"}
    
    # Create super admin
    admin_doc = {
        "id": str(uuid.uuid4()),
        "name": "Super Admin",
        "email": "admin@store.com",
        "password_hash": hash_password("admin123"),
        "phone": None,
        "role": "super_admin",
        "is_active": True,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": datetime.now(timezone.utc).isoformat()
    }
    await db.users.insert_one(admin_doc)
    
    # Create categories
    categories = [
        {"id": str(uuid.uuid4()), "name": "Electronics", "slug": "electronics", "description": "Electronic devices and gadgets", "is_active": True},
        {"id": str(uuid.uuid4()), "name": "Fashion", "slug": "fashion", "description": "Clothing and accessories", "is_active": True},
        {"id": str(uuid.uuid4()), "name": "Home & Furniture", "slug": "home-furniture", "description": "Home decor and furniture", "is_active": True},
        {"id": str(uuid.uuid4()), "name": "Beauty", "slug": "beauty", "description": "Skincare and beauty products", "is_active": True},
    ]
    await db.categories.insert_many(categories)
    
    # Create sample products
    products = [
        {
            "id": str(uuid.uuid4()),
            "name": "Wireless Headphones",
            "description": "Premium wireless headphones with noise cancellation and 30-hour battery life. Perfect for music lovers and professionals.",
            "price": 199.99,
            "category_id": categories[0]["id"],
            "stock_quantity": 50,
            "images": ["https://images.unsplash.com/photo-1655466677040-fa44a99567b4?crop=entropy&cs=srgb&fm=jpg&ixid=M3w4NjAzMjh8MHwxfHNlYXJjaHwzfHxtaW5pbWFsaXN0JTIwcHJvZHVjdCUyMHBob3RvZ3JhcGh5JTIwd2hpdGUlMjBiYWNrZ3JvdW5kfGVufDB8fHx8MTc3MTQxNzExNXww&ixlib=rb-4.1.0&q=85"],
            "sku": "SKU-HEADPHONES-001",
            "status": "active",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat()
        },
        {
            "id": str(uuid.uuid4()),
            "name": "Minimalist Watch",
            "description": "Elegant minimalist watch with leather strap. Water-resistant and perfect for any occasion.",
            "price": 149.99,
            "category_id": categories[1]["id"],
            "stock_quantity": 30,
            "images": ["https://images.unsplash.com/photo-1625860191460-10a66c7384fb?crop=entropy&cs=srgb&fm=jpg&ixid=M3w4NjAzMjh8MHwxfHNlYXJjaHwxfHxtaW5pbWFsaXN0JTIwcHJvZHVjdCUyMHBob3RvZ3JhcGh5JTIwd2hpdGUlMjBiYWNrZ3JvdW5kfGVufDB8fHx8MTc3MTQxNzExNXww&ixlib=rb-4.1.0&q=85"],
            "sku": "SKU-WATCH-001",
            "status": "active",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat()
        },
        {
            "id": str(uuid.uuid4()),
            "name": "Modern Desk Chair",
            "description": "Ergonomic desk chair with adjustable height and lumbar support. Designed for comfort during long work hours.",
            "price": 299.99,
            "category_id": categories[2]["id"],
            "stock_quantity": 15,
            "images": ["https://images.unsplash.com/photo-1590605464732-c291c01c9db9?crop=entropy&cs=srgb&fm=jpg&ixid=M3w3NTY2NjZ8MHwxfHNlYXJjaHwyfHxtaW5pbWFsaXN0JTIwc2tpbmNhcmUlMjBib3R0bGUlMjBhbmQlMjBtb2Rlcm4lMjBjaGFpcnxlbnwwfHx8fDE3NzE0MTcxMzB8MA&ixlib=rb-4.1.0&q=85"],
            "sku": "SKU-CHAIR-001",
            "status": "active",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat()
        },
        {
            "id": str(uuid.uuid4()),
            "name": "Organic Face Serum",
            "description": "Natural face serum with vitamin C and hyaluronic acid. Brightens skin and reduces fine lines.",
            "price": 49.99,
            "category_id": categories[3]["id"],
            "stock_quantity": 100,
            "images": ["https://images.unsplash.com/photo-1572014788455-fdd2bc0e9e51?crop=entropy&cs=srgb&fm=jpg&ixid=M3w3NTY2NjZ8MHwxfHNlYXJjaHwzfHxtaW5pbWFsaXN0JTIwc2tpbmNhcmUlMjBib3R0bGUlMjBhbmQlMjBtb2Rlcm4lMjBjaGFpcnxlbnwwfHx8fDE3NzE0MTcxMzB8MA&ixlib=rb-4.1.0&q=85"],
            "sku": "SKU-SERUM-001",
            "status": "active",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat()
        },
        {
            "id": str(uuid.uuid4()),
            "name": "Linen Shirt",
            "description": "Premium linen shirt in classic white. Breathable fabric perfect for summer. Available in all sizes.",
            "price": 79.99,
            "category_id": categories[1]["id"],
            "stock_quantity": 45,
            "images": ["https://images.unsplash.com/flagged/photo-1578053239820-32b8a3ffbbb9?crop=entropy&cs=srgb&fm=jpg&ixid=M3w3NTY2NjZ8MHwxfHNlYXJjaHw0fHxtaW5pbWFsaXN0JTIwc2tpbmNhcmUlMjBib3R0bGUlMjBhbmQlMjBtb2Rlcm4lMjBjaGFpcnxlbnwwfHx8fDE3NzE0MTcxMzB8MA&ixlib=rb-4.1.0&q=85"],
            "sku": "SKU-SHIRT-001",
            "status": "active",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat()
        },
        {
            "id": str(uuid.uuid4()),
            "name": "Portable Speaker",
            "description": "Compact Bluetooth speaker with powerful bass. Waterproof design, perfect for outdoor adventures.",
            "price": 89.99,
            "category_id": categories[0]["id"],
            "stock_quantity": 8,
            "images": ["https://images.unsplash.com/photo-1655466677040-fa44a99567b4?crop=entropy&cs=srgb&fm=jpg&ixid=M3w4NjAzMjh8MHwxfHNlYXJjaHwzfHxtaW5pbWFsaXN0JTIwcHJvZHVjdCUyMHBob3RvZ3JhcGh5JTIwd2hpdGUlMjBiYWNrZ3JvdW5kfGVufDB8fHx8MTc3MTQxNzExNXww&ixlib=rb-4.1.0&q=85"],
            "sku": "SKU-SPEAKER-001",
            "status": "active",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat()
        },
        {
            "id": str(uuid.uuid4()),
            "name": "Ceramic Vase Set",
            "description": "Set of 3 minimalist ceramic vases. Perfect for modern home decor. Handcrafted with attention to detail.",
            "price": 59.99,
            "category_id": categories[2]["id"],
            "stock_quantity": 25,
            "images": ["https://images.unsplash.com/photo-1590605464732-c291c01c9db9?crop=entropy&cs=srgb&fm=jpg&ixid=M3w3NTY2NjZ8MHwxfHNlYXJjaHwyfHxtaW5pbWFsaXN0JTIwc2tpbmNhcmUlMjBib3R0bGUlMjBhbmQlMjBtb2Rlcm4lMjBjaGFpcnxlbnwwfHx8fDE3NzE0MTcxMzB8MA&ixlib=rb-4.1.0&q=85"],
            "sku": "SKU-VASE-001",
            "status": "active",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat()
        },
        {
            "id": str(uuid.uuid4()),
            "name": "Night Repair Cream",
            "description": "Luxurious night cream that repairs and rejuvenates skin while you sleep. With retinol and peptides.",
            "price": 69.99,
            "category_id": categories[3]["id"],
            "stock_quantity": 60,
            "images": ["https://images.unsplash.com/photo-1572014788455-fdd2bc0e9e51?crop=entropy&cs=srgb&fm=jpg&ixid=M3w3NTY2NjZ8MHwxfHNlYXJjaHwzfHxtaW5pbWFsaXN0JTIwc2tpbmNhcmUlMjBib3R0bGUlMjBhbmQlMjBtb2Rlcm4lMjBjaGFpcnxlbnwwfHx8fDE3NzE0MTcxMzB8MA&ixlib=rb-4.1.0&q=85"],
            "sku": "SKU-CREAM-001",
            "status": "active",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat()
        },
    ]
    await db.products.insert_many(products)
    
    return {"message": "Seed data created successfully", "admin_email": "admin@store.com", "admin_password": "admin123"}

# ============ STATIC FILES ============

app.mount("/api/uploads", StaticFiles(directory=str(ROOT_DIR / 'uploads')), name="uploads")

# Include the router
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()