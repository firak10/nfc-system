import os
import io
import base64
import datetime
from typing import Optional
from fastapi import FastAPI, HTTPException, Depends, Header, Request, UploadFile, File, Form, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
import psycopg2
from psycopg2.extras import RealDictCursor
from passlib.context import CryptContext
import jwt
from PIL import Image

# ==========================================
# CONFIGURAÇÕES E VARIÁVEIS DE AMBIENTE
# ==========================================
DATABASE_URL = os.getenv("DATABASE_URL")
JWT_SECRET = os.getenv("JWT_SECRET", "troque_essa_chave_secreta_em_producao_123456")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_DAYS = 7

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI(title="Aproxime Aqui - API", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Conexão com o Banco de Dados
def get_db():
    conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
    try:
        yield conn
    finally:
        conn.close()

# Helper para redimensionamento e compressão de foto em WebP (~20KB a 30KB) em Data URI Base64
def process_photo_to_base64(file_bytes: bytes) -> str:
    img = Image.open(io.BytesIO(file_bytes))
    
    if img.mode in ("RGBA", "P"):
        img = img.convert("RGB")
        
    img.thumbnail((400, 500), Image.Resampling.LANCZOS)
    output_buffer = io.BytesIO()
    img.save(output_buffer, format="WEBP", quality=80, optimize=True)
    
    encoded = base64.b64encode(output_buffer.getvalue()).decode("utf-8")
    return f"data:image/webp;base64,{encoded}"

# ==========================================
# HELPER FUNCTIONS (AUTH & JWT)
# ==========================================
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=ACCESS_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=ALGORITHM)

def get_current_user(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token de autenticação ausente ou inválido.",
        )
    
    token = authorization.split(" ")[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Sessão expirada. Faça login novamente.",
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido.",
        )

def require_superadmin(current_user: dict = Depends(get_current_user)):
    if current_user.get("role") != "superadmin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Acesso negado. Requer privilégios de SuperAdmin.",
        )
    return current_user

# ==========================================
# MODELOS DE DADOS (PYDANTIC)
# ==========================================
class LoginSchema(BaseModel):
    email: EmailStr
    password: str

class NFCLoginSchema(BaseModel):
    token: str

class CreateCompanySchema(BaseModel):
    name: str
    document: Optional[str] = None
    admin_email: EmailStr
    admin_password: str
    admin_name: str

# ==========================================
# ROTAS PÚBLICAS (VALIDAÇÃO DE CRACHÁ NFC)
# ==========================================

@app.get("/v1/validate/{user_id}")
def validate_card(user_id: str, request: Request, conn=Depends(get_db)):
    with conn.cursor() as cur:
        # Busca os dados do usuário portador do crachá
        cur.execute("""
            SELECT u.id, u.full_name, u.document, u.photo_url, u.status, u.expires_at, c.name as company_name
            FROM users u
            LEFT JOIN companies c ON c.id = u.company_id
            WHERE u.id = %s
        """, (user_id,))
        user = cur.fetchone()

        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, 
                detail="Usuário / Cartão não encontrado."
            )

        # Registra o log de auditoria da leitura NFC
        client_ip = request.client.host if request.client else None
        user_agent = request.headers.get("user-agent")

        cur.execute("""
            INSERT INTO access_logs (user_id, ip_address, user_agent)
            VALUES (%s, %s, %s)
        """, (user["id"], client_ip, user_agent))
        conn.commit()

        return {
            "id": str(user["id"]),
            "full_name": user["full_name"],
            "document": user["document"],
            "photo_url": user["photo_url"],
            "company_name": user["company_name"],
            "status": user["status"],
            "expires_at": user["expires_at"].isoformat() if user["expires_at"] else None,
            "is_valid": user["status"] == "active"
        }

# ==========================================
# ROTAS DE AUTENTICAÇÃO DE PAINEL
# ==========================================

@app.post("/v1/auth/login")
def login(data: LoginSchema, conn=Depends(get_db)):
    with conn.cursor() as cur:
        cur.execute("""
            SELECT id, company_id, email, password_hash, full_name, role, login_token, active 
            FROM admin_users 
            WHERE email = %s
        """, (data.email,))
        user = cur.fetchone()

        if not user or not verify_password(data.password, user["password_hash"]):
            raise HTTPException(status_code=401, detail="E-mail ou senha incorretos.")

        if not user["active"]:
            raise HTTPException(status_code=403, detail="Usuário inativo.")

        token = create_access_token({
            "sub": str(user["id"]),
            "email": user["email"],
            "full_name": user["full_name"],
            "role": user["role"],
            "company_id": str(user["company_id"]) if user["company_id"] else None
        })

        return {
            "access_token": token,
            "token_type": "bearer",
            "user": {
                "id": str(user["id"]),
                "full_name": user["full_name"],
                "email": user["email"],
                "role": user["role"],
                "company_id": str(user["company_id"]) if user["company_id"] else None,
                "login_token": str(user["login_token"])
            }
        }

@app.post("/v1/auth/nfc-login")
def nfc_login(data: NFCLoginSchema, conn=Depends(get_db)):
    with conn.cursor() as cur:
        cur.execute("""
            SELECT id, company_id, email, full_name, role, login_token, active 
            FROM admin_users 
            WHERE login_token = %s
        """, (data.token,))
        user = cur.fetchone()

        if not user:
            raise HTTPException(status_code=404, detail="Cartão de login não cadastrado ou token inválido.")

        if not user["active"]:
            raise HTTPException(status_code=403, detail="Usuário inativo.")

        token = create_access_token({
            "sub": str(user["id"]),
            "email": user["email"],
            "full_name": user["full_name"],
            "role": user["role"],
            "company_id": str(user["company_id"]) if user["company_id"] else None
        })

        return {
            "access_token": token,
            "token_type": "bearer",
            "user": {
                "id": str(user["id"]),
                "full_name": user["full_name"],
                "email": user["email"],
                "role": user["role"],
                "company_id": str(user["company_id"]) if user["company_id"] else None,
                "login_token": str(user["login_token"])
            }
        }

# ==========================================
# ROTAS SUPERADMIN (GESTÃO DE EMPRESAS)
# ==========================================

@app.post("/v1/superadmin/companies")
def create_company(data: CreateCompanySchema, current_user=Depends(require_superadmin), conn=Depends(get_db)):
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO companies (name, document) 
                VALUES (%s, %s) 
                RETURNING id, name, document, active, created_at
            """, (data.name, data.document))
            company = cur.fetchone()
            company_id = company["id"]

            hashed_pwd = get_password_hash(data.admin_password)
            cur.execute("""
                INSERT INTO admin_users (company_id, email, password_hash, full_name, role)
                VALUES (%s, %s, %s, %s, 'admin')
                RETURNING id, email, full_name, login_token
            """, (company_id, data.admin_email, hashed_pwd, data.admin_name))
            admin_user = cur.fetchone()

            conn.commit()

            return {
                "company": {
                    "id": str(company["id"]),
                    "name": company["name"],
                    "document": company["document"],
                    "active": company["active"]
                },
                "admin_user": {
                    "id": str(admin_user["id"]),
                    "full_name": admin_user["full_name"],
                    "email": admin_user["email"],
                    "login_nfc_url": f"https://login.aproximeaqui.com.br/?token={admin_user['login_token']}"
                }
            }
    except psycopg2.IntegrityError:
        conn.rollback()
        raise HTTPException(status_code=400, detail="Este e-mail já está em uso por outro usuário.")
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/v1/superadmin/companies")
def list_companies(current_user=Depends(require_superadmin), conn=Depends(get_db)):
    with conn.cursor() as cur:
        cur.execute("""
            SELECT c.id, c.name, c.document, c.active, c.created_at,
                   u.id as admin_id, u.email as admin_email, u.full_name as admin_name, u.login_token
            FROM companies c
            LEFT JOIN admin_users u ON u.company_id = c.id AND u.role = 'admin'
            ORDER BY c.created_at DESC
        """)
        companies = cur.fetchall()

        result = []
        for item in companies:
            result.append({
                "id": str(item["id"]),
                "name": item["name"],
                "document": item["document"],
                "active": item["active"],
                "created_at": item["created_at"].isoformat() if item["created_at"] else None,
                "admin": {
                    "id": str(item["admin_id"]) if item["admin_id"] else None,
                    "name": item["admin_name"],
                    "email": item["admin_email"],
                    "login_nfc_url": f"https://login.aproximeaqui.com.br/?token={item['login_token']}" if item["login_token"] else None
                }
            })
        return result

# ==========================================
# ROTAS DO PAINEL ADMIN (GESTÃO DE USUÁRIOS / CRACHÁS)
# ==========================================

@app.get("/v1/admin/users")
def list_users(current_user=Depends(get_current_user), conn=Depends(get_db)):
    company_id = current_user.get("company_id")
    role = current_user.get("role")

    with conn.cursor() as cur:
        if role == "superadmin":
            cur.execute("""
                SELECT u.id, u.company_id, u.full_name, u.document, u.photo_url, u.status, u.created_at, c.name as company_name
                FROM users u
                LEFT JOIN companies c ON c.id = u.company_id
                ORDER BY u.created_at DESC
            """)
        else:
            cur.execute("""
                SELECT id, company_id, full_name, document, photo_url, status, created_at
                FROM users
                WHERE company_id = %s
                ORDER BY created_at DESC
            """, (company_id,))

        users = cur.fetchall()
        for u in users:
            u["id"] = str(u["id"])
            if "company_id" in u and u["company_id"]:
                u["company_id"] = str(u["company_id"])
            if u.get("created_at"):
                u["created_at"] = u["created_at"].isoformat()
        return users

@app.post("/v1/admin/users", status_code=status.HTTP_201_CREATED)
async def create_user(
    full_name: str = Form(...),
    document: Optional[str] = Form(None),
    company_id: Optional[str] = Form(None),
    file: UploadFile = File(...),
    current_user=Depends(get_current_user),
    conn=Depends(get_db)
):
    # Se não passar company_id, atribui a empresa do admin logado
    target_company_id = company_id if (current_user.get("role") == "superadmin" and company_id) else current_user.get("company_id")

    if not target_company_id:
        raise HTTPException(status_code=400, detail="É necessário informar a empresa do usuário.")

    # Processa e comprime a foto para WebP (~20KB em Data URI)
    file_bytes = await file.read()
    compressed_photo_base64 = process_photo_to_base64(file_bytes)

    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO users (company_id, full_name, document, photo_url, status)
            VALUES (%s, %s, %s, %s, 'active')
            RETURNING id, company_id, full_name, document, photo_url, status, created_at
        """, (target_company_id, full_name, document, compressed_photo_base64))
        
        new_user = cur.fetchone()
        conn.commit()

        new_user["id"] = str(new_user["id"])
        new_user["company_id"] = str(new_user["company_id"])
        new_user["created_at"] = new_user["created_at"].isoformat()
        return new_user

# ==========================================
# REVOGAÇÃO / REGENERAÇÃO DE TOKEN NFC DE LOGIN
# ==========================================

@app.post("/v1/admin/revoke-nfc-token")
def revoke_my_nfc_token(current_user=Depends(get_current_user), conn=Depends(get_db)):
    with conn.cursor() as cur:
        cur.execute("""
            UPDATE admin_users 
            SET login_token = gen_random_uuid() 
            WHERE id = %s 
            RETURNING login_token
        """, (current_user["sub"],))
        
        result = cur.fetchone()
        conn.commit()

        if not result:
            raise HTTPException(status_code=404, detail="Usuário não encontrado.")

        new_token = str(result["login_token"])
        return {
            "message": "Cartão antigo revogado com sucesso! O token anterior foi invalidado.",
            "new_token": new_token,
            "new_login_nfc_url": f"https://login.aproximeaqui.com.br/?token={new_token}"
        }

@app.post("/v1/superadmin/admins/{admin_id}/revoke-nfc-token")
def revoke_company_admin_nfc_token(admin_id: str, current_user=Depends(require_superadmin), conn=Depends(get_db)):
    with conn.cursor() as cur:
        cur.execute("""
            UPDATE admin_users 
            SET login_token = gen_random_uuid() 
            WHERE id = %s 
            RETURNING id, full_name, email, login_token
        """, (admin_id,))
        
        result = cur.fetchone()
        conn.commit()

        if not result:
            raise HTTPException(status_code=404, detail="Administrador não encontrado.")

        new_token = str(result["login_token"])
        return {
            "message": f"Cartão de {result['full_name']} revogado com sucesso!",
            "admin_id": str(result["id"]),
            "new_token": new_token,
            "new_login_nfc_url": f"https://login.aproximeaqui.com.br/?token={new_token}"
        }