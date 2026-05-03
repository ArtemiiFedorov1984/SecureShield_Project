import time
import jwt
import bcrypt
import logging
from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

app = FastAPI()

# Константы (Task 2) [cite: 12]
SECRET_KEY = "super_secret_key"
ALGORITHM = "HS256"
security = HTTPBearer()

# Настройка логирования (Task 6) 
logging.basicConfig(filename='security.log', level=logging.WARNING, 
                    format='%(asctime)s - %(message)s')

# База данных (Task 1) 
# Мы оставляем предустановленных юзеров + даем возможность регистрировать новых
users_db = {
    "admin1": {"password": bcrypt.hashpw(b"admin123", bcrypt.gensalt()), "role": "Admin"},
    "user1": {"password": bcrypt.hashpw(b"user123", bcrypt.gensalt()), "role": "User"}
}

# --- Вспомогательные функции ---

def get_current_user(cred: HTTPAuthorizationCredentials = Depends(security)):
    # Task 3: Валидация токена [cite: 13]
    token = cred.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"JWT Error: {str(e)}")

# --- Эндпоинты ---

@app.post("/register")
def register(username: str, password: str, role: str = "User"):
    # Task 1: Безопасное хранение (хеширование) 
    if username in users_db:
        raise HTTPException(status_code=400, detail="User already exists")
    
    hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    users_db[username] = {"password": hashed_pw, "role": role}
    return {"message": f"User {username} registered successfully as {role}"}

@app.post("/login")
def login(username: str, password: str):
    # Task 2: Проверка и выдача JWT [cite: 12]
    user = users_db.get(username)
    if not user or not bcrypt.checkpw(password.encode('utf-8'), user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    payload = {
        "username": username, 
        "role": user["role"], 
        "exp": time.time() + 3600
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return {"access_token": token}

@app.get("/profile")
def profile(user: dict = Depends(get_current_user)):
    # Task 4: Доступ для User и Admin [cite: 18]
    return {"message": f"Welcome, {user['username']}!", "role": user['role']}

@app.delete("/user/{user_id}")
def delete_user(user_id: int, user: dict = Depends(get_current_user)):
    # Task 4: Доступ только для Admin [cite: 18]
    if user["role"] != "Admin":
        # Task 6: Defensive Logging 
        logging.warning(f"Unauthorized DELETE attempt on user {user_id} by {user['username']}")
        raise HTTPException(status_code=403, detail="Forbidden: Admins only")
    
    return {"message": f"User {user_id} has been deleted by Admin"}