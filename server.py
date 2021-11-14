import typing
import hmac
import hashlib
import base64
import json
from fastapi import FastAPI, Form, Cookie
from fastapi.responses import Response
from typing import Optional

app = FastAPI()

SECRET_KEY = 'ed3f76b2cf276324c1434cb89aa76f8583ce360da04b53af6e89f5d9862b7cea' 
PASSWORD_SALT = '90540e7b89f648733b67f679c07ee100577d6c938732de4f1a8f66b70b1d4195'

users = {
    "alexey@user.com": {
        "name" : "alexey", 
        "password": "5d60cdaffd52b289352e82032169a4c6359b1aa64c9dcba683c7e2d5374a76ae",
        "balance" : 100000
    }, "petr@user.com":
    {
        "name" : "petr",
        "password": "445544",
        "balance": 555555
    }
}

def sign_data(data : str) -> str:
    """Возвращает подписанные данные data"""
    return hmac.new(
        SECRET_KEY.encode(),
        msg=data.encode(),
        digestmod=hashlib.sha256
    ).hexdigest().upper()

def get_username_from_signed_string(username_signed:str) -> Optional[str]:
    username_base64, sign = username_signed.split(".")
    username = base64.b64decode(username_base64.encode()).decode()
    valid_sign = sign_data(username)
    if hmac.compare_digest(valid_sign, sign):
        return username

def verify_password(username : str, password : str) -> bool:
    password_hash = hashlib.sha256((password + PASSWORD_SALT).encode()).hexdigest().lower()
    stored_password_hash = users[username]["password"].lower()
    return  password_hash == stored_password_hash

@app.get("/")
def index_page(username : Optional[str] = Cookie(default=None)):
    with open('templates/login.html', 'r') as f:
        login_page = f.read()
    if not username:
        return Response(login_page, media_type="text/html")
    valid_username = get_username_from_signed_string(username)
    if not valid_username:
        response = Response (login_page, media_type="text/html")
        response.delete_cookie(key="username")
        return response
    try:
        user = users[valid_username]
    except KeyError:
        response = Response (login_page, media_type="text/html")
        response.delete_cookie(key="username")
        return response
    return Response(f"Привет {users[valid_username]['name']}, ваш баланс {users[valid_username]['balance']} руб", media_type="text/html")

@app.post("/login")
def login(username : str = Form(...), password : str = Form(...)):
    user = users.get(username)
    if not user or not verify_password(username, password):
        return Response(json.dumps(
        {
            "success" : False,
            "message" : "Ya vas ne znau!"
        }
        ), media_type="application/json")

    response = Response(json.dumps(
        {
            "success" : True,
            "message": f"Привет {user['name']}, ваш баланс {user['balance']} руб"
        }
    ), media_type="application/json")
    
    username_signed = f"{base64.b64encode(username.encode()).decode()}.{sign_data(username)}"
    response.set_cookie(key="username", value=username_signed)
    return response