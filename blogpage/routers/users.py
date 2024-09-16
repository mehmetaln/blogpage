import json
from certifi import contents
from cryptography import fernet
from cryptography.fernet import Fernet
from fastapi import APIRouter, HTTPException, status
from schema import *
from database import *
from functions import *
from config import *

router = APIRouter(
    prefix="/users",
    tags=["1.User Page"]
)






@router.post("/user/create", status_code=status.HTTP_201_CREATED, summary="create user")
async def create_user(user: UserCreate):
    conn,cursor = get_database()
    try:
        cursor = conn.cursor()

        check_user = fetchone__dict2dot(cursor,f'''SELECT * FROM users WHERE lower(contents->>'username') = lower('{user.username}')''')
        if check_user:
            close_connection(cursor, conn)
            raise HTTPException(status_code=400, detail="Username already exists.")

        check_email = fetchone__dict2dot(cursor,f'''SELECT * FROM users WHERE lower(contents->>'email') = lower('{user.email}')''')
        if check_email:
            close_connection(cursor,conn)
            raise HTTPException(status_code=400, detail="Email already exists.")



        if user.password != user.password_confirm:
            close_connection(cursor, conn)
            raise HTTPException(status_code=400, detail="Passwords do not match.")


        password_checking(user.password)

        fernet_key = Fernet.generate_key()
        anektar = Fernet(fernet_key)
        encrypted_password = anektar.encrypt(user.password.encode()).decode()

        date_joined = datetime.now().isoformat()


        contents = {
            "username": user.username,
            "email": user.email,
            "password": encrypted_password,
            "is_active": True,
            "user_group": user.user_group,
            "fernet_key": fernet_key.decode(),
            "first_name": None,
            "last_name": None,
            "date_joined": date_joined,
            "last_login": None,
            "birth_date": None,
            "gender": user.gender
        }

        cursor.execute(f'''INSERT INTO users(contents) VALUES (%s)''', [json.dumps(contents)])
        conn.commit()
        close_connection(cursor, conn)
        return {"message": "User successfully created."}


    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal Server Error: {str(e)}")


# qwrqwrqwrq

@router.post("/token", status_code=status.HTTP_201_CREATED, summary=" user login")
async def login_user(user:UserLogin):
    conn, cursor = get_database()

    cursor = conn.cursor()

    cursor.execute("SELECT contents FROM users WHERE lower(contents->>'username') = lower(%s)", (user.username,))
    user_data = cursor.fetchone()

    if not user_data:
        close_connection(cursor, conn)
        raise HTTPException(status_code=400, detail="Username does not exist.")


    contents = user_data[0]

    fernet_key = contents['fernet_key'].encode()
    anekter = Fernet(fernet_key)  # Byte formatında anahtarla Fernet oluştur
    decrypted_password = anekter.decrypt(contents['password'].encode()).decode()


    if decrypted_password != user.password:
        close_connection(cursor, conn)
        raise HTTPException(status_code=400, detail="Password do not match.")

    access_token = create_access_token(data={"sub": user.username})
    print(f"access_token: {access_token}")


    close_connection(cursor, conn)
    return {"access_token": access_token, "token_type": "bearer"}




@router.get("/user/profile")
async def user_profile(current_user: dict = Depends(user_is_active)):
    return {"message": f"Profile details for {current_user['username']}"}


@router.get("/user/test/")
async def test_user(current_user: dict = Depends(get_current_user)):
    return {"message": f"Current user: {current_user['username']}"}

# asfasf
