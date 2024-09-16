from enum import Enum

from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr, Field
from typing import Optional
from datetime import datetime


class Gender(str, Enum):
    male = "erkek"
    female = "kadın"

class UserGroupEnum(int, Enum):
    admin = 1
    superuser = 2
    user = 3

class UserCreate(BaseModel):
    email: EmailStr
    gender: Gender
    username: str
    password: str
    password_confirm: str
    user_group: UserGroupEnum = UserGroupEnum.user  # Varsayılan olarak 'user'

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/users/token")
