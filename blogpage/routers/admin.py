from fastapi import APIRouter, HTTPException, status

from functions import *

router = APIRouter(
    prefix="/admin",
    tags=["2. Admin Page"]
)



@router.get("/dashboard")
async def admin_dashboard(current_user: dict = Depends(get_admin_user)):
    return {"message": f"Welcome Admin {current_user['username']}"}
""
