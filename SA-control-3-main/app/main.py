from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBasicCredentials, HTTPBasic
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from . import models, security, db, RBAC
from .config import MODE, DOCS_USER, DOCS_PASSWORD
import secrets
import json

limiter = Limiter(key_func=get_remote_address)

app = FastAPI(title = "KR3")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

if MODE == "PROD":
    app.docs_url = None
    app.redoc_url = None
    app.openapi_url = None

def basic_auth(credentials: HTTPBasicCredentials = Depends(HTTPBasic())):
    correct_username = secrets.compare_digest(credentials.username, DOCS_USER)
    correct_password = secrets.compare_digest(credentials.password, DOCS_PASSWORD)

    if not (correct_username and correct_password):
        raise HTTPException(
            status_code=401,
            detail="Unauthorized",
            headers={"WWW-Authenticate": "Basic"}
        )
    return True

#6.1
@app.get("/protected_resource")
async def protected_resource(credentials: HTTPBasicCredentials = Depends(security.security_basic)):
    with db.get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT username, hashed_password FROM users WHERE username = ?", (credentials.username,))
        db_user = cursor.fetchone()

    if db_user is None or not security.verify_password(credentials.password, db_user["hashed_password"]):
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"}
        )
    return {"message": "You got my secret, welcome"}

#6.2
@app.post("/register")
@limiter.limit("1/minute")
async def register(request: Request, user: models.UserCreate):
    with db.get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM users WHERE username = ?", (user.username,))

        if cursor.fetchone():
            raise HTTPException(
                status_code=409,
                detail="User already exists"
            )
        hashed = security.hash_password(user.password)
        cursor.execute("INSERT INTO users (username, hashed_password) VALUES (?, ?)", (user.username, hashed))
        conn.commit()

    return models.UserOut(username=user.username, roles=["user"])

@app.get("/login")
async def login(credentials: HTTPBasicCredentials = Depends(security.security_basic)):
    with db.get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT username, hashed_password, roles FROM users WHERE username = ?", (credentials.username,))
        db_user = cursor.fetchone()

    if db_user is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"}
        )
    if not security.verify_password(credentials.password, db_user["hashed_password"]):
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"}
        )
    
    return {"message": f"Welcome, {credentials.username}!"}

#6.4, 6.5
@app.post("/jwt/login", response_model=models.Token)
@limiter.limit("5/minute")
async def jwt_login(request: Request, login: models.LoginRequest):
    with db.get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT username, hashed_password FROM users WHERE username = ?", (login.username,))
        db_user = cursor.fetchone()

    if db_user is None:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )
    if not security.verify_password(login.password, db_user["hashed_password"]):
        raise HTTPException(
            status_code=401,
            detail="Authorization failed"
        )
    
    token = security.create_jwt_token({"sub": login.username})
    return {"access_token": token, "token_type": "bearer"}

@app.get("/jwt/protected_resource")
async def jwt_protected(username: str = Depends(security.get_current_user)):
    return {"message": f"Access granted for {username}"}

#7.1
@app.get("/admin")
async def admin_endpoint(_: str = Depends(RBAC.RoleChecker(["admin"]))):
    return {"message": "Welcome, admin!"}

@app.get("/user")
async def user_endpoint(_: str = Depends(RBAC.RoleChecker(["admin", "user"]))):
    return {"message": "Welcome, user!"}

@app.get("/guest")
async def guest_endpoint(_: str = Depends(RBAC.RoleChecker(["admin", "user", "guest"]))):
    return {"message": "Welcome, guest!"}

#8.2
@app.post("/todos", response_model=models.TodoOut)
async def create_todo(todo: models.TodoCreate):
    with db.get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO todos (title, description) VALUES (?, ?)", (todo.title, todo.description))
        conn.commit()
        todo_id = cursor.lastrowid

    return models.TodoOut(id=todo_id, title=todo.title, description=todo.description)

@app.get("/todos/{todo_id}", response_model=models.TodoOut)
async def get_todo(todo_id: int):
    with db.get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, title, description, completed FROM todos WHERE id = ?", (todo_id,))
        row = cursor.fetchone()

    if row is None:
        raise HTTPException(
            status_code=404,
            detail="Todo not found"
        )

    return models.TodoOut(
        id=row["id"],
        title=row["title"],
        description=row["description"],
        completed=bool(row["completed"])
    )

@app.patch("/todos/{todo_id}/toggle")
async def toggle_todo(todo_id: int):
    with db.get_db_connection() as conn:
        cursor = conn.cursor()
        
        cursor.execute("SELECT completed FROM todos WHERE id = ?", (todo_id,))
        row = cursor.fetchone()
        
        if row is None:
            raise HTTPException(
                status_code=404,
                detail="Todo not found"
            )
        new_status = not row["completed"]
        cursor.execute("UPDATE todos SET completed = ? WHERE id = ?", (new_status, todo_id))
        conn.commit()
        
        cursor.execute("SELECT id, title, description, completed FROM todos WHERE id = ?", (todo_id,))
        updated_row = cursor.fetchone()
        
    return {
        "id": updated_row["id"],
        "title": updated_row["title"],
        "description": updated_row["description"],
        "completed": updated_row["completed"]
    }

@app.put("/todos/{todo_id}", response_model=models.TodoOut)
async def update_todo(todo_id: int, todo: models.TodoCreate):
    with db.get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE todos SET title = ?, description = ? WHERE id = ?", (todo.title, todo.description, todo_id))
        conn.commit()

        if cursor.rowcount == 0:
            raise HTTPException(
                status_code=404,
                detail="Todo not found"
            )
        cursor.execute("SELECT id, title, description, completed FROM todos WHERE id = ?", (todo_id,))
        row = cursor.fetchone()

    return models.TodoOut(id=row["id"], title=row["title"], description=row["description"], completed=row["completed"])

@app.delete("/todos/{todo_id}")
async def delete_todo(todo_id: int):
    with db.get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM todos WHERE id = ?", (todo_id,))
        conn.commit()
        
        if cursor.rowcount == 0:
            raise HTTPException(
                status_code=404,
                detail="Todo not found"
            )
        
    return {"message": "Todo deleted"}

@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})