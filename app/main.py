#!/usr/bin/env python
# -*- coding: utf-8 -*-
import pysodium
import os
from bson import ObjectId
from datetime import datetime, timedelta
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.gzip import GZipMiddleware
from jose import JWTError, jwt
from models import db, Data, Token, TokenData, User, UserIn, UserInDB
from passlib.context import CryptContext
from pydantic import BaseModel, Field
from typing import Optional

# to get a string like this run:
# openssl rand -hex 32
SECRET_KEY = os.getenv(
    "SECRET_KEY",
    "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Server secret
server_key = os.getenv("SERVER_KEY", "CUSTOM_SERVER_KEY_HERE")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/token")

app = FastAPI()

# Add gzip to improve network bandwith requirements
app.add_middleware(GZipMiddleware, minimum_size=1000)


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_user(username: str):
    user_dict = db.users.find_one({"username": username})
    print("user: %s" % user_dict)
    return UserInDB(**user_dict)


def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(username=token_data.username)
    if user is None:
        raise credentials_exception
    return User(**user.dict())


async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


def update_db(domains):
    """
    receives a list of domains and will update mongodb collection
    for each prefix using $addToSet and @each modifier to only include new ones.
    """
    # Connect to DB and get the domains collection
    print("domains %s" % domains)
    collection = db.domains

    for k,v in domains.items():
        document_id = k
        # print("document_id: %s" % k)
        # print("domains: %s" % v)
        # print("type(domains): %s" % type(v))
        result = collection.update(
            {"_id": document_id},
            {"$addToSet": {"domains": {"$each": list(v)}}})


def process_domains(data: Data):
    """
    Process new domains and add new to db
    """
    results = {}
    for domain_raw in data.domains:
        print("new domain: %s" % domain_raw)
        # TODO normalize domain
        domain = str.encode(domain_raw)
        # Fist use SHA512 hashing function on the normalized domain
        hashed_domain = pysodium.crypto_hash_sha512(domain)
        # print("original hashed domain %s" % hashed_domain)
        hashed_domain_hex = hashed_domain.hex()
        # print("hex hashed domain %s" % hashed_domain_hex)
        prefix = 'prefix_%s' % hashed_domain_hex[:4]
        # Map the hash to the elliptic curve
        mapped_domain = pysodium.crypto_core_ristretto255_from_hash(hashed_domain)
        # print("result of hash to group function: %s" % mapped_domain)
        # Validate mapped point
        pysodium.crypto_core_ristretto255_is_valid_point(mapped_domain)
        # print("valid point on elliptic curve")
        # Blind mapped point using servers key
        b = bytes.fromhex(server_key)
        blinded_domain = pysodium.crypto_scalarmult_ristretto255(b, mapped_domain)
        # print("blinded result by server key: %s" % blinded_domain)
        # Validate blinded mapped point
        pysodium.crypto_core_ristretto255_is_valid_point(blinded_domain)
        # print("valid point on elliptic curve %s" % pysodium.crypto_core_ristretto255_is_valid_point(blinded_domain))
        blinded_domain_hex = blinded_domain.hex()
        # print("blinded domain hex: %s" % blinded_domain_hex)
        if prefix not in results.keys():
            results[prefix] = {blinded_domain_hex}
        else:
            if blinded_domain_hex in results[prefix]:
                print("Found a duplicate!! for domain: %s" % domain_raw)
            else:
                results[prefix].add(blinded_domain_hex)

    output = {k:{"domains":list(v)} for k, v in results.items()}
    update_db(results)


#TODO get a html page with static elements
@app.get("/")
def read_root():
    b = bytes.fromhex(server_key)
    a = pysodium.crypto_core_ristretto255_scalar_random()
    return {"Hello": a.hex(), "key": b.hex()}


# OAuth2
@app.post("/api/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


# User handling endpoints
@app.get("/api/users/me")
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user


# @app.get('/api/users')
# async def list_users():
#     users = []
#     for user in db.users.find():
#         users.append(User(**user))
#     return {'users': users}


# Not needed anymore
# @app.post("/api/users")
# async def create_user(user: UserIn):
#     if hasattr(user, 'id'):
#         delattr(user, 'id')
#     hashed_password = get_password_hash(user.password)
#     user_in_db = UserInDB(**user.dict(), hashed_password=hashed_password, _id = str(ObjectId()))
#     print(user_in_db.dict(by_alias=True))
#     ret = db.users.insert_one(user_in_db.dict(by_alias=True))
#     return {'user': user}


# Domain management endpoints
@app.get("/api/checkdomain")
def read_check_domain(hash_prefix: str, domain: str):
    # construct mongo document id
    document_id = "prefix_{0}".format(hash_prefix)
    try:
        client_domain = bytes.fromhex(domain)
        valid = pysodium.crypto_core_ristretto255_is_valid_point(client_domain)
        if not valid:
            raise Exception
    except Exception as e:
        return {"error": "not a valid blinded domain using ristretto255"}

    # Double blind received client domain
    b = bytes.fromhex(server_key)
    client_domain_blinded = pysodium.crypto_scalarmult_ristretto255(b, client_domain)

    # Retrieve stored data for the given prefix
    collection = db.domains
    result = collection.find_one(document_id)
    return {"double_blinded_domain": client_domain_blinded.hex(), "malicious_domains": result["domains"]}


@app.post("/api/updatedomains", status_code=status.HTTP_202_ACCEPTED)
async def update_domains(data: Data, background_tasks: BackgroundTasks, token: str = Depends(oauth2_scheme)):
    background_tasks.add_task(process_domains, data)
    return {"message": "New domains are being processed in the background", "token": token}

@app.post("/api/updatedomains/test")
def update_domains_test(domain_raw: str, token: str = Depends(oauth2_scheme)):
    domain = str.encode(domain_raw)
    # Fist use SHA512 hashing function on the normalized domain
    hashed_domain = pysodium.crypto_hash_sha512(domain)
    # print("original hashed domain %s" % hashed_domain)
    hashed_domain_hex = hashed_domain.hex()
    prefix = 'prefix_%s' % hashed_domain_hex[:4]
    # Map the hash to the elliptic curve
    mapped_domain = pysodium.crypto_core_ristretto255_from_hash(hashed_domain)
    b = bytes.fromhex(server_key)
    blinded_domain = pysodium.crypto_scalarmult_ristretto255(b, mapped_domain)
    blinded_domain_hex = blinded_domain.hex()
    result = db.domains.find_one(prefix, projection={"_id": False})
    if blinded_domain_hex in result["domains"]:
        return {"message": "Seems that updating is working fine"}
    else:
        return {"message": "Not found...did you type too fast?"}


    return {"message": "New domains are being processed in the background", "token": token}
