from flask import  request
from app import modules
from app.config import Config
from . import gen_md5, random_choices
from .conn import conn_db

salt = 'arlsalt!@#'

def user_login(username = None, password = None):
    if not username or not password:
        return

    query = {"username": username, "password": gen_md5(salt + password)}
    user = conn_db('user').find_one(query)
    if user:
        # 生成新的token
        new_token = gen_md5(random_choices(50))
        # 创建一个新的文档，包含用户名和新的token
        new_document = query.copy()  # 复制查询条件，避免直接修改原始查询
        new_document["token"] = new_token
        # 插入新的文档到数据库
        conn_db('user').insert_one(new_document)
        return {
            "username": username,
            "token": new_token,
            "type": "login" 
            }


def user_login_header():
    token = request.headers.get("Token") or request.args.get("token")

    if not Config.AUTH:
        return True

    item = {
        "username": "ARL-API",
        "token": Config.API_KEY,
        "type": "api"
    }


    if not token:
        return False

    if token == Config.API_KEY:
        return item


    data = conn_db('user').find_one({"token": token})
    if data:
        item["username"] = data.get("username")
        item["token"] = token
        item["type"] = "login"
        return item

    return False



def user_logout(token):
    if user_login_header():
        conn_db('user').update_one({"token": token}, {"$set": {"token": None}})


def change_pass(token, old_password, new_password):
    query = {"token": token, "password": gen_md5(salt + old_password)}
    data = conn_db('user').find_one(query)
    if data:
        conn_db('user').update_one({"token": token}, {"$set": {"password": gen_md5(salt + new_password)}})
        return True
    else:
        return False


import functools


def auth(func):
    ret = {
        "message": "not login",
        "code": 401,
        "data": {}
    }

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        if Config.AUTH and not user_login_header():
            return  ret

        return func(*args, **kwargs)

    return wrapper
