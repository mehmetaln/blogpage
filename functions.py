from datetime import timedelta, datetime
from dataclasses import *
from jose import JWTError, jwt
from datetime import timezone
from fastapi import Depends, HTTPException, status
from sqlalchemy.testing.suite.test_reflection import users

from schema import  *
from database import *

from config import *
from database import get_database, close_connection


class Dict2Dot(dict):
    def __getattr__(self, key):
        if key in self:
            return self[key]
        else:
            raise AttributeError(f"'{self.__class__.__name__}' objesinde '{key}' anahtarı bulunamadı.")


def fetchone__dict2dot(cursor, sql):
    cursor.execute(sql)
    sql_result = cursor.fetchone()
    if sql_result:
        return Dict2Dot(sql_result)
    else:
        return None


def fetchall__dict2dot(cursor, sql):
    cursor.execute(sql)
    sql_result = cursor.fetchall()
    result_list = []
    if sql_result:
        for result in sql_result:
            new_result = Dict2Dot(result)
            result_list.append(new_result)
        return result_list
    else:
        return result_list


def password_checking(password: str):
    # Şifre minimum 8 karakter uzunluğunda olmalı
    if len(password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters long")
    # Şifre en az bir rakam içermeli
    if not any(char.isdigit() for char in password):
        raise HTTPException(status_code=400, detail="Password must contain at least one digit")
    return True


# TOKEN işlemler






SECRET_KEY = "mysecretkey"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 300


def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})

    # Kullanıcı adı gibi bilgilerin token içine doğru eklenip eklenmediğini yazdır
    print("Token içine kodlanacak veri:", to_encode)

    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

    # Token'ı geri çözerek içeriğini kontrol edelim
    decoded_payload = jwt.decode(encoded_jwt, SECRET_KEY, algorithms=[ALGORITHM])
    print("Oluşturulan token içeriği:", decoded_payload)  # Token içeriğini yazdır

    return encoded_jwt


async def get_current_user(token: str = Depends(oauth2_scheme)):  # Token doğrulama
    try:
        # Token'ı çöz ve payload'u kontrol et
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        print("Çözülen token payload'u:", payload)  # Debugging için ekleyin

        username: str = payload.get("sub")

        if username is None:
            print("Token'da 'sub' bulunamadı, geçersiz token.")  # Debugging
            raise HTTPException(status_code=401, detail="Geçersiz token")

    except JWTError as e:
        print(f"JWT Hatası: {e}")  # JWT hatasını yazdır
        raise HTTPException(status_code=401, detail="Kimlik doğrulama başarısız")

    # Veritabanı sorgusu
    conn, cursor = get_database()
    try:
        cursor.execute("SELECT contents FROM users WHERE lower(contents->>'username') = lower(%s)", (username,))
        user_data = cursor.fetchone()

        # Sorgudan sonuç çıkmazsa kontrol edin
        if user_data is None:
            raise HTTPException(status_code=401, detail="Kullanıcı bulunamadı")

        # user_data'nın tuple olduğunu varsayarak ilk elemanı döndürüyoruz
        return user_data[0] if isinstance(user_data, tuple) else user_data

    finally:
        close_connection(cursor, conn)




# Kullanıcı aktifliğini kontrol etme
def user_is_login(current_user:dict= Depends(get_current_user)):
    conn,cursor = get_database()
    cursor.execute("SELECT contents FROM users WHERE lower(contents->>'username') = lower(%s)", (current_user['username'],))
    user_data = cursor.fetchone()
    print(user_data)


    if not user_data:
        close_connection(cursor, conn)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    if user_data.get('user_is_login') is False:
        close_connection(cursor, conn)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User is not logged in")

    close_connection(cursor, conn)

    print(user_data)
    return user_data

def get_admin_user(current_user: dict = Depends(get_current_user)):
    if current_user['user_group'] != 1:  # Sadece admin erişebilir
        raise HTTPException(status_code=403, detail="Admin access only")
    return current_user
