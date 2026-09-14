import os
import uuid
import jwt
from datetime import datetime, timedelta, timezone
import httpx
import asyncpg
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from pydantic import BaseModel

app = FastAPI(title="ARAQUM ID Auth")

# Список разрешенных доменов экосистемы
ORIGINS = [
    CORSMiddleware,
    allow_origins=ORIGINS,  # Указываем конкретный список вместо "*"
    allow_credentials=True, # Браузер теперь пропустит credentials: 'include'
    allow_methods=["*"],
    allow_headers=["*"],
]

# Настройка CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Переменные окружения из .env
DATABASE_URL = os.getenv("ConnectionStrings__Postgres")
VK_CLIENT_ID = os.getenv("VK_CLIENT_ID")
VK_CLIENT_SECRET = os.getenv("VK_CLIENT_SECRET")
VK_REDIRECT_URI = os.getenv("VK_REDIRECT_URI", "https://id.araqum.ru/api/v1/auth/oauth/vk/callback")
FRONTEND_URL = os.getenv("FRONTEND_URL", "https://id.araqum.com")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "fK42JFVRIVfV452B525mnjbvBS5FFgfbnnSS452KHGD426GBfH25QbfgbJDHJLKD5JYUbgfDSFJnVSKJFHB4VG639FfbfVGMnb")


# Временное хранилище одноразовых кодов (в продакшене лучше Redis, для старта подойдет словарь)
AUTH_CODES = {}

async def get_db():
    return await asyncpg.connect(DATABASE_URL)

class VerifyCodeRequest(BaseModel):
    code: str
    device_id: str | None = Field(None, alias="deviceId")

    class Config:
        populate_by_name = True

@app.get("/api/v1/auth/oauth/vk/login")
async def vk_login():
    url = (
        f"https://id.vk.ru/authorize?"
        f"response_type=code&client_id={VK_CLIENT_ID}"
        f"&redirect_uri={VK_REDIRECT_URI}"
    )
    return RedirectResponse(url)

@app.get("/api/v1/auth/oauth/vk/callback")
async def vk_callback(code: str):
    async with httpx.AsyncClient() as client:
        # 1. Получаем токен от VK
        token_response = await client.post(
            "https://api.vk.ru/oauth2/auth",
            data={
                "grant_type": "authorization_code",
                "client_id": VK_CLIENT_ID,
                "client_secret": VK_CLIENT_SECRET,
                "redirect_uri": VK_REDIRECT_URI,
                "code": code,
            },
        )
        token_data = token_response.json()
        if "access_token" not in token_data:
            raise HTTPException(status_code=400, detail="Ошибка получения токена VK")

        access_token = token_data["access_token"]
        user_id_vk = str(token_data.get("user_id"))

        # 2. Получаем профиль VK
        user_response = await client.get(
            "https://api.vk.ru/method/users.get",
            params={
                "user_ids": user_id_vk,
                "fields": "photo_200,domain",
                "access_token": access_token,
                "v": "5.131",
            },
        )
        user_info = user_response.json().get("response", [{}])[0]

    # 3. База данных
    conn = await get_db()
    try:
        user = await conn.fetchrow("SELECT id FROM users WHERE vk_id = $1", user_id_vk)
        if not user:
            user = await conn.fetchrow("INSERT INTO users (vk_id) VALUES ($1) RETURNING id", user_id_vk)
        db_user_id = user["id"]
    finally:
        await conn.close()

    # 4. Генерируем одноразовый временный код (живет 60 секунд)
    one_time_code = str(uuid.uuid4())
    AUTH_CODES[one_time_code] = {
        "user_id": db_user_id,
        "vk_id": user_id_vk,
        "first_name": user_info.get("first_name", ""),
        "last_name": user_info.get("last_name", ""),
        "avatar": user_info.get("photo_200", ""),
        "vk_link": f"https://vk.com/{user_info.get('domain', 'id' + user_id_vk)}",
        "expires_at": datetime.now(timezone.utc) + timedelta(seconds=60)
    }

    # 5. Возвращаем пользователя на .com ТОЛЬКО с одноразовым кодом
    return RedirectResponse(f"{FRONTEND_URL}/auth/callback?code={one_time_code}")


# 6. Эндпоинт ДЛЯ C# БЭКЕНДА: обмен одноразового кода на профиль и JWT
@app.post("/api/v1/auth/verify-code")
async def verify_code(payload: VerifyCodeRequest):
    async with httpx.AsyncClient() as client:
        vk_payload = {
            "grant_type": "authorization_code",
            "client_id": "54769644",
            "client_secret": VK_CLIENT_SECRET,  # Защищенный ключ из кабинета VK
            "redirect_uri": "https://araqum.ru",
            "code": payload.code,
            "device_id": payload.device_id or ""
        }
        
        # Обмен авторизационного кода VK ID v2
        vk_res = await client.post("https://id.vk.com/oauth2/auth", data=vk_payload)
        vk_data = vk_res.json()
        
        if "access_token" not in vk_data:
            print(f"[VK ERROR] {vk_data}", flush=True)
            raise HTTPException(status_code=401, detail=vk_data)
            
            # Извлекаем данные пользователя из ответа VK
            user_info = vk_data.get("user", {})
            data = {
                "user_id": vk_data.get("user_id") or user_info.get("id"),
                "first_name": user_info.get("first_name", ""),
                "last_name": user_info.get("last_name", ""),
                "avatar": user_info.get("avatar", ""),
                "vk_link": f"https://vk.com/id{vk_data.get('user_id')}"
            }

    # 3. Генерируем JWT для .NET (id.araqum.com)
    jwt_payload = {
        "sub": str(data["user_id"]),
        "first_name": data.get("first_name"),
        "last_name": data.get("last_name"),
        "avatar": data.get("avatar"),
        "vk_link": data.get("vk_link"),
        "exp": datetime.now(timezone.utc) + timedelta(days=7)
    }
    
    token = jwt.encode(jwt_payload, JWT_SECRET_KEY, algorithm="HS256")
    
    return {
        "access_token": token,
        "user": jwt_payload
    }