#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
from bson import ObjectId
from pydantic import BaseModel, Field
from pymongo import MongoClient
from typing import Optional

# Mongo Config
MONGO_DATABASE_USERNAME = os.getenv("MONGO_INITDB_ROOT_USERNAME", "CUSTOM_MONGO_USERNAME_HERE")
MONGO_DATABASE_PASSWORD = os.getenv("MONGO_INITDB_ROOT_PASSWORD", "CUSTOM_MONGO_PASSWORD_HERE")
MONGO_URI = "mongodb://{0}:{1}@mongo-a".format(MONGO_DATABASE_USERNAME, MONGO_DATABASE_PASSWORD)
MONGO_PORT = 27017

# Retrieve stored data for the given prefix
client = MongoClient(MONGO_URI, MONGO_PORT)
db = client.kako


class Data(BaseModel):
    domains: set


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None


class PyObjectId(ObjectId):

    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v):
        if not ObjectId.is_valid(v):
            raise ValueError('Invalid objectid')
        return ObjectId(v)

    @classmethod
    def __modify_schema__(cls, field_schema):
        field_schema.update(type='string')


class User(BaseModel):
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    disabled: Optional[bool] = False


class UserIn(User):
    password: str


class UserInDB(User):
    id: Optional[PyObjectId] = Field(alias='_id')
    hashed_password: str

    class Config:
        arbitrary_types_allowed = True
        json_encoders = {
            ObjectId: str
        }

