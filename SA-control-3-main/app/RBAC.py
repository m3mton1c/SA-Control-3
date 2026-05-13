from fastapi import HTTPException, Depends
from .db import get_db_connection
from .security import get_current_user
import json

class RoleChecker:
    def __init__(self, allowed_roles: list[str]):
        self.allowed_roles = allowed_roles

    def __call__(self, username: str = Depends(get_current_user)):
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT roles FROM users WHERE username = ?", (username,))
            row = cursor.fetchone()
        if not row:
            raise HTTPException(
                status_code=403,
                detail="User not found"
            )
        
        roles = json.loads(row["roles"])
        if not any(role in roles for role in self.allowed_roles):
            raise HTTPException(
                status_code=403,
                detail="Not enough permissions"
            )
        return username