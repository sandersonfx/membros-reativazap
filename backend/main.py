"""Área de Membros — ReativaZap.
Auth própria (sem Supabase Auth): senha com bcrypt, sessão por token opaco
guardado em `sessoes`. Banco Postgres dedicado (self-hosted no Coolify).
"""
import os
import re
import secrets
import string
import hmac
import hashlib
import time
import logging
from datetime import datetime, timedelta, timezone

import bcrypt
import psycopg2
import psycopg2.extras
import httpx
from fastapi import FastAPI, HTTPException, Request, Header, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from dotenv import load_dotenv
load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("membros")

DB_DSN = os.getenv("DATABASE_URL", "")
ADMIN_SECRET = os.getenv("ADMIN_SECRET", "")
CAKTO_WEBHOOK_SECRET = os.getenv("CAKTO_WEBHOOK_SECRET", "")
UAZAPI_URL = os.getenv("UAZAPI_URL", "")
UAZAPI_INSTANCE_TOKEN = os.getenv("UAZAPI_INSTANCE_TOKEN", "")  # a decidir qual número
FRONTEND_URL = os.getenv("FRONTEND_URL", "https://membros.reativazap.com")

app = FastAPI(title="Área de Membros ReativaZap")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


def db():
    return psycopg2.connect(DB_DSN, cursor_factory=psycopg2.extras.RealDictCursor)


@app.get("/health")
def health():
    return {"status": "ok", "service": "membros-reativazap"}


def _normalizar_whatsapp(numero: str) -> str:
    digitos = re.sub(r"\D", "", numero or "")
    if not digitos.startswith("55"):
        digitos = "55" + digitos
    return digitos


def _gerar_senha_temporaria(tamanho: int = 8) -> str:
    alfabeto = string.ascii_uppercase + string.digits
    return "".join(secrets.choice(alfabeto) for _ in range(tamanho))


def _hash_senha(senha: str) -> str:
    return bcrypt.hashpw(senha.encode(), bcrypt.gensalt()).decode()


def _checar_senha(senha: str, hash_: str) -> bool:
    try:
        return bcrypt.checkpw(senha.encode(), hash_.encode())
    except Exception:
        return False


def _criar_sessao(conn, aluna_id: str) -> str:
    token = secrets.token_urlsafe(32)
    expira = datetime.now(timezone.utc) + timedelta(days=30)
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO sessoes (token, aluna_id, expira_em) VALUES (%s, %s, %s)",
            (token, aluna_id, expira),
        )
    conn.commit()
    return token


def _aluna_por_token(authorization: str | None) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Token ausente")
    token = authorization.removeprefix("Bearer ").strip()
    conn = db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """SELECT a.* FROM sessoes s JOIN alunas a ON a.id = s.aluna_id
                   WHERE s.token = %s AND s.expira_em > now()""",
                (token,),
            )
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=401, detail="Sessão inválida ou expirada")
            return row
    finally:
        conn.close()


async def _enviar_whatsapp(numero: str, texto: str) -> None:
    if not UAZAPI_URL or not UAZAPI_INSTANCE_TOKEN:
        logger.warning("UAZAPI não configurado ainda — mensagem não enviada: %s", texto)
        return
    async with httpx.AsyncClient(timeout=15) as client:
        await client.post(
            f"{UAZAPI_URL}/send/text",
            json={"number": numero, "text": texto},
            headers={"token": UAZAPI_INSTANCE_TOKEN},
        )


class LoginInput(BaseModel):
    identificador: str  # whatsapp ou email
    senha: str


@app.post("/auth/login")
def login(dados: LoginInput):
    conn = db()
    try:
        with conn.cursor() as cur:
            ident = dados.identificador.strip()
            whatsapp = _normalizar_whatsapp(ident) if any(c.isdigit() for c in ident) else None
            cur.execute(
                "SELECT * FROM alunas WHERE email = %s OR whatsapp = %s",
                (ident.lower(), whatsapp),
            )
            aluna = cur.fetchone()
        if not aluna or not _checar_senha(dados.senha, aluna["senha_hash"]):
            raise HTTPException(status_code=401, detail="Login ou senha incorretos")
        token = _criar_sessao(conn, aluna["id"])
        return {
            "token": token,
            "nome": aluna["nome"],
            "precisa_trocar_senha": aluna["precisa_trocar_senha"],
        }
    finally:
        conn.close()


class TrocarSenhaInput(BaseModel):
    senha_nova: str


@app.post("/auth/trocar-senha")
def trocar_senha(dados: TrocarSenhaInput, authorization: str | None = Header(None)):
    aluna = _aluna_por_token(authorization)
    if len(dados.senha_nova) < 6:
        raise HTTPException(status_code=400, detail="Senha muito curta (mínimo 6 caracteres)")
    conn = db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE alunas SET senha_hash = %s, precisa_trocar_senha = false WHERE id = %s",
                (_hash_senha(dados.senha_nova), aluna["id"]),
            )
        conn.commit()
        return {"ok": True}
    finally:
        conn.close()


@app.get("/me/cursos")
def meus_cursos(authorization: str | None = Header(None)):
    """Todo produto ativo aparece na lista — os liberados vêm com os
    cursos/aulas completos, os não comprados vêm só com nome + link de
    checkout (mostra cadeado no front)."""
    aluna = _aluna_por_token(authorization)
    conn = db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT produto_id FROM acessos WHERE aluna_id = %s AND status = 'ativo'",
                (aluna["id"],),
            )
            liberados = {r["produto_id"] for r in cur.fetchall()}

            cur.execute("SELECT * FROM produtos WHERE ativo = true ORDER BY nome")
            produtos = cur.fetchall()

            resultado = []
            for produto in produtos:
                tem_acesso = produto["id"] in liberados
                item = {
                    "produto_id": produto["id"],
                    "nome": produto["nome"],
                    "descricao": produto["descricao"],
                    "liberado": tem_acesso,
                    "checkout_url": None if tem_acesso else produto["checkout_url"],
                    "cursos": [],
                }
                if tem_acesso:
                    cur.execute(
                        "SELECT * FROM cursos WHERE produto_id = %s ORDER BY ordem, titulo",
                        (produto["id"],),
                    )
                    for curso in cur.fetchall():
                        cur.execute(
                            "SELECT id, titulo, descricao, youtube_video_id, ordem FROM aulas WHERE curso_id = %s ORDER BY ordem, titulo",
                            (curso["id"],),
                        )
                        aulas = cur.fetchall()
                        item["cursos"].append({
                            "curso_id": curso["id"],
                            "titulo": curso["titulo"],
                            "descricao": curso["descricao"],
                            "aulas": aulas,
                        })
                resultado.append(item)
            return {"nome": aluna["nome"], "produtos": resultado}
    finally:
        conn.close()


# ── Webhook Cakto: cria a conta automaticamente após a compra ──────────────

def _validar_assinatura_cakto(raw_body: bytes, timestamp: str, signature: str) -> bool:
    if not CAKTO_WEBHOOK_SECRET or not timestamp or not signature:
        return False
    try:
        if abs(time.time() - int(timestamp)) > 5 * 60:
            return False
    except Exception:
        return False
    esperado = hmac.new(CAKTO_WEBHOOK_SECRET.encode(), f"{timestamp}.".encode() + raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(signature, f"v1={esperado}")


_EVENTO_ATIVA = {"purchase_approved", "subscription_created", "subscription_renewed", "subscription_resumed"}
_EVENTO_DESATIVA = {"purchase_refused", "subscription_canceled", "subscription_renewal_refused", "refund", "chargeback"}


@app.post("/webhook/cakto")
async def webhook_cakto(request: Request):
    raw = await request.body()
    timestamp = request.headers.get("X-Cakto-Timestamp", "")
    signature = request.headers.get("X-Cakto-Signature", "")

    import json as _json
    try:
        payload = _json.loads(raw) if raw else {}
    except Exception:
        payload = {}

    valido = _validar_assinatura_cakto(raw, timestamp, signature)
    if not valido and payload.get("secret"):
        valido = hmac.compare_digest(str(payload.get("secret")), CAKTO_WEBHOOK_SECRET or "")
    if not valido:
        raise HTTPException(status_code=401, detail="assinatura inválida")

    evento = payload.get("event")
    data = payload.get("data") or {}
    offer_id = (data.get("offer") or {}).get("short_id") or data.get("offer_id") or ""
    customer = data.get("customer") or {}
    whatsapp = _normalizar_whatsapp(customer.get("phone") or "")
    email = (customer.get("email") or "").lower() or None
    nome = customer.get("name") or "Aluna"

    if not whatsapp:
        return {"ok": True, "ignored": True, "motivo": "sem telefone"}

    conn = db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM produtos WHERE cakto_offer_id = %s", (str(offer_id),))
            produto = cur.fetchone()
        if not produto:
            logger.warning("Produto não encontrado pro offer_id=%s", offer_id)
            return {"ok": True, "ignored": True, "motivo": "produto não cadastrado"}

        with conn.cursor() as cur:
            cur.execute("SELECT * FROM alunas WHERE whatsapp = %s", (whatsapp,))
            aluna = cur.fetchone()

        senha_gerada = None
        if not aluna:
            senha_gerada = _gerar_senha_temporaria()
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO alunas (nome, email, whatsapp, senha_hash, precisa_trocar_senha)
                       VALUES (%s, %s, %s, %s, true) RETURNING *""",
                    (nome, email, whatsapp, _hash_senha(senha_gerada)),
                )
                aluna = cur.fetchone()
            conn.commit()

        if evento in _EVENTO_ATIVA:
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO acessos (aluna_id, produto_id, cakto_order_id, status)
                       VALUES (%s, %s, %s, 'ativo')
                       ON CONFLICT (aluna_id, produto_id) DO UPDATE SET status = 'ativo', cakto_order_id = EXCLUDED.cakto_order_id""",
                    (aluna["id"], produto["id"], str(data.get("id") or "")),
                )
            conn.commit()

            if senha_gerada:
                texto = (
                    f"🎉 Bem-vinda, {nome}!\n\nSeu acesso à área de membros do {produto['nome']} já está liberado.\n\n"
                    f"🔗 {FRONTEND_URL}\n👤 Login: {whatsapp}\n🔑 Senha: {senha_gerada}\n\n"
                    "Troque sua senha no primeiro acesso."
                )
            else:
                texto = f"🎉 Novo acesso liberado: {produto['nome']}!\n\n🔗 {FRONTEND_URL}"
            await _enviar_whatsapp(whatsapp, texto)

        elif evento in _EVENTO_DESATIVA:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE acessos SET status = 'cancelado' WHERE aluna_id = %s AND produto_id = %s",
                    (aluna["id"], produto["id"]),
                )
            conn.commit()

        return {"ok": True}
    finally:
        conn.close()


# ── Admin simples (protegido por ADMIN_SECRET) ──────────────────────────────

def _checar_admin(key: str):
    if not ADMIN_SECRET or key != ADMIN_SECRET:
        raise HTTPException(status_code=403, detail="Acesso negado")


class ProdutoInput(BaseModel):
    nome: str
    slug: str
    descricao: str | None = None
    cakto_offer_id: str | None = None
    checkout_url: str


@app.post("/admin/produtos")
def criar_produto(dados: ProdutoInput, key: str = Query(...)):
    _checar_admin(key)
    conn = db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO produtos (nome, slug, descricao, cakto_offer_id, checkout_url)
                   VALUES (%s,%s,%s,%s,%s) RETURNING *""",
                (dados.nome, dados.slug, dados.descricao, dados.cakto_offer_id, dados.checkout_url),
            )
            produto = cur.fetchone()
        conn.commit()
        return produto
    finally:
        conn.close()


class CursoInput(BaseModel):
    produto_id: str
    titulo: str
    descricao: str | None = None
    ordem: int = 0


@app.post("/admin/cursos")
def criar_curso(dados: CursoInput, key: str = Query(...)):
    _checar_admin(key)
    conn = db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO cursos (produto_id, titulo, descricao, ordem) VALUES (%s,%s,%s,%s) RETURNING *",
                (dados.produto_id, dados.titulo, dados.descricao, dados.ordem),
            )
            curso = cur.fetchone()
        conn.commit()
        return curso
    finally:
        conn.close()


class AulaInput(BaseModel):
    curso_id: str
    titulo: str
    descricao: str | None = None
    youtube_video_id: str
    ordem: int = 0


@app.post("/admin/aulas")
def criar_aula(dados: AulaInput, key: str = Query(...)):
    _checar_admin(key)
    conn = db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO aulas (curso_id, titulo, descricao, youtube_video_id, ordem)
                   VALUES (%s,%s,%s,%s,%s) RETURNING *""",
                (dados.curso_id, dados.titulo, dados.descricao, dados.youtube_video_id, dados.ordem),
            )
            aula = cur.fetchone()
        conn.commit()
        return aula
    finally:
        conn.close()


@app.get("/admin/overview")
def admin_overview(key: str = Query(...)):
    _checar_admin(key)
    conn = db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS n FROM alunas")
            alunas = cur.fetchone()["n"]
            cur.execute("SELECT COUNT(*) AS n FROM acessos WHERE status = 'ativo'")
            acessos_ativos = cur.fetchone()["n"]
            cur.execute("SELECT id, nome, slug FROM produtos ORDER BY nome")
            produtos = cur.fetchall()
        return {"alunas": alunas, "acessos_ativos": acessos_ativos, "produtos": produtos}
    finally:
        conn.close()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 8200)))
