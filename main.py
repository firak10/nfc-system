import io
import uuid
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Request, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from PIL import Image

from database import engine, Base, get_db
import models

# Evento de inicialização do FastAPI (substitui o evento antigo de startup)
@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        models.Base.metadata.create_all(bind=engine)
        print(">>> Conexão com o banco estabelecida e tabelas verificadas no Supabase! <<<")
    except Exception as e:
        print(f">>> ERRO CRÍTICO NA CONEXÃO COM O BANCO: {e} <<<")
        raise e
    yield

app = FastAPI(
    title="NFC Validation API",
    version="1.0.0",
    lifespan=lifespan
)

# CORS liberado para o front-end (sistema.aproximeaqui.com.br)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Helper para redimensionamento e compressão de foto em WebP (~20KB a 30KB)
def process_photo(file_bytes: bytes) -> bytes:
    img = Image.open(io.BytesIO(file_bytes))
    
    if img.mode in ("RGBA", "P"):
        img = img.convert("RGB")
        
    img.thumbnail((400, 500), Image.Resampling.LANCZOS)
    output_buffer = io.BytesIO()
    img.save(output_buffer, format="WEBP", quality=80, optimize=True)
    return output_buffer.getvalue()

# Healthcheck simples para verificar se a API está online
@app.get("/")
def health_check():
    return {"status": "online", "message": "NFC Validation API rodando!"}

# 1. Rota Pública: Validação do Cartão NFC
@app.get("/v1/validate/{user_id}")
def validate_card(user_id: uuid.UUID, request: Request, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, 
            detail="Usuário / Cartão não encontrado."
        )
    
    # Registra o log de leitura no banco
    client_ip = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    
    log = models.AccessLog(
        user_id=user.id,
        ip_address=client_ip,
        user_agent=user_agent
    )
    db.add(log)
    db.commit()
    
    return {
        "id": str(user.id),
        "full_name": user.full_name,
        "document": user.document,
        "photo_url": user.photo_url,
        "status": user.status,
        "expires_at": user.expires_at,
        "is_valid": user.status == "active"
    }

# 2. Rota Admin: Cadastro de Usuário com Upload de Foto
@app.post("/v1/admin/users", status_code=status.HTTP_201_CREATED)
async def create_user(
    full_name: str,
    document: str = None,
    company_id: uuid.UUID = None,
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    file_bytes = await file.read()
    compressed_photo = process_photo(file_bytes)
    
    # URL temporária até configurarmos o R2/Supabase Storage
    mock_photo_url = f"https://seu-storage.com/photos/{uuid.uuid4()}.webp"

    new_user = models.User(
        company_id=company_id,
        full_name=full_name,
        document=document,
        photo_url=mock_photo_url,
        status="active"
    )
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    return new_user
