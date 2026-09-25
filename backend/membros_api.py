"""Área de Membros — API própria sobre Postgres (sem Supabase).

Por que este arquivo existe: o site (`membros.reativazap.com`) foi construído para o
HTTP do Supabase (auth + rest + storage). Postgres puro não fala HTTP, então esta é a
camada que fala. As tabelas aqui têm **exatamente** os nomes e tipos que o front já
usa (`courses`, `modules`, `lessons`, `enrollments`, `lesson_progress`, `profiles`,
`user_roles`) — assim o front muda de endereço, não de schema.

Diferenças de desenho, de propósito:
- sessão própria: bcrypt + token opaco em `sessoes_app` (sem GoTrue)
- imagens ficam NO BANCO (`midias.bytes`), servidas por `/api/media/{tipo}/{id}`, e a
  coluna `cover_url`/`image_url`/`avatar_url` aponta pro nosso endpoint
- quem compra tem o acesso liberado pelo EMAIL (OnProfit/Cakto)

Regra que já custou caro: rota nova SEMPRE antes do bloco `if __name__ == "__main__"`
do main.py, senão o uvicorn.run bloqueia e a rota não existe em produção.
"""
import os
import re
import json
import secrets
import time
import logging
from datetime import datetime, timedelta, timezone
from uuid import UUID

import bcrypt
import psycopg2
import psycopg2.extras
from fastapi import APIRouter, HTTPException, Request, Header, Query, Form, UploadFile, File
from fastapi.responses import Response
from pydantic import BaseModel

logger = logging.getLogger("membros")

router = APIRouter()

SESSION_DAYS = int(os.getenv("SESSION_DAYS", "30"))
ADMIN_SECRET = os.getenv("ADMIN_SECRET", "")
ID_RE = re.compile(r"^[a-z_][a-z0-9_]*$")
MAX_BYTES = int(os.getenv("MEDIA_MAX_BYTES", str(8 * 1024 * 1024)))
ADMIN_EMAILS = [e.strip().lower() for e in
                os.getenv("ADMIN_EMAILS", "sanderson_genuino@hotmail.com").split(",") if e.strip()]

# Tabelas que a rede pode tocar. Nomes e colunas são os MESMOS do front.
TABELAS = {
    "profiles":        {"tabela": "profiles",        "escopo": "id"},
    "user_roles":      {"tabela": "user_roles",      "escopo": "user_id"},
    "courses":         {"tabela": "courses",         "escopo": None},
    "modules":         {"tabela": "modules",         "escopo": "course_id"},
    "lessons":         {"tabela": "lessons",         "escopo": "module_id"},
    "enrollments":     {"tabela": "enrollments",     "escopo": "user_id"},
    "lesson_progress": {"tabela": "lesson_progress", "escopo": "user_id"},
    "banners":         {"tabela": "banners",         "escopo": None},
}
# Tabelas em que o aluno comum pode gravar (só nas próprias linhas)
ESCRITA_ALUNO = {"profiles": "id", "lesson_progress": "user_id"}
APAGAR_ALUNO = {"lesson_progress"}
# tabelas com coluna updated_at (enrollments e user_roles NÃO têm)
TEM_UPDATED_AT = {"profiles", "courses", "modules", "lessons", "lesson_progress", "banners"}
# Relações que o front pede embutidas: select('*, lessons(*)')
EMBEDS = {"modules": {"lessons": ("lessons", "module_id")},
          "courses": {"modules": ("modules", "course_id")}}

DDL = """
CREATE TABLE IF NOT EXISTS profiles (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email TEXT UNIQUE NOT NULL,
  senha_hash TEXT NOT NULL,
  full_name TEXT NOT NULL DEFAULT '',
  avatar_url TEXT,
  precisa_trocar_senha BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS user_roles (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  role TEXT NOT NULL DEFAULT 'student',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (user_id, role)
);
CREATE TABLE IF NOT EXISTS courses (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  title TEXT NOT NULL,
  slug TEXT NOT NULL UNIQUE,
  description TEXT NOT NULL DEFAULT '',
  cover_url TEXT,
  checkout_url TEXT,
  is_published BOOLEAN NOT NULL DEFAULT FALSE,
  show_in_catalog BOOLEAN NOT NULL DEFAULT TRUE,
  liberado_para_todos BOOLEAN NOT NULL DEFAULT FALSE,
  secao TEXT NOT NULL DEFAULT '',
  position INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS modules (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  course_id UUID NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  cover_url TEXT,
  position INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS lessons (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  module_id UUID NOT NULL REFERENCES modules(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  youtube_url TEXT NOT NULL DEFAULT '',
  image_url TEXT,
  materials TEXT NOT NULL DEFAULT '[]',
  duration_minutes INTEGER NOT NULL DEFAULT 0,
  position INTEGER NOT NULL DEFAULT 0,
  is_published BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS enrollments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  course_id UUID NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
  granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (user_id, course_id)
);
CREATE TABLE IF NOT EXISTS lesson_progress (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  lesson_id UUID NOT NULL REFERENCES lessons(id) ON DELETE CASCADE,
  completed BOOLEAN NOT NULL DEFAULT FALSE,
  completed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (user_id, lesson_id)
);
CREATE TABLE IF NOT EXISTS sessoes_app (
  token TEXT PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  criado_em TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expira_em TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS midias (
  tipo TEXT NOT NULL,
  ref_id UUID NOT NULL,
  bytes BYTEA NOT NULL,
  mime TEXT NOT NULL DEFAULT 'image/jpeg',
  atualizado_em TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (tipo, ref_id)
);
CREATE TABLE IF NOT EXISTS acessos_pendentes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email TEXT NOT NULL,
  course_id UUID NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
  origem TEXT,
  pedido_id TEXT,
  criado_em TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (email, course_id)
);
CREATE TABLE IF NOT EXISTS mapa_ofertas (
  oferta TEXT PRIMARY KEY,
  course_id UUID NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
  criado_em TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS banners (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  titulo TEXT NOT NULL DEFAULT '',
  imagem_url TEXT,
  link TEXT NOT NULL DEFAULT '',
  local TEXT NOT NULL DEFAULT 'vitrine',
  position INTEGER NOT NULL DEFAULT 0,
  ativo BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE courses  ADD COLUMN IF NOT EXISTS duration_minutes INTEGER NOT NULL DEFAULT 0;
ALTER TABLE courses  ADD COLUMN IF NOT EXISTS liberado_para_todos BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE courses  ADD COLUMN IF NOT EXISTS secao TEXT NOT NULL DEFAULT '';
ALTER TABLE lessons  ADD COLUMN IF NOT EXISTS is_free BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE lessons  ADD COLUMN IF NOT EXISTS materials TEXT NOT NULL DEFAULT '[]';
"""


def db():
    return psycopg2.connect(os.getenv("DATABASE_URL", ""), cursor_factory=psycopg2.extras.RealDictCursor)


def criar_tabelas():
    """Idempotente. Roda no boot; nunca apaga nada das tabelas antigas."""
    conn = db()
    try:
        with conn.cursor() as cur:
            cur.execute(DDL)
        conn.commit()
        logger.info("membros_api: tabelas garantidas")
        return True
    finally:
        conn.close()


# ── senha, papel e sessão ────────────────────────────────────────────────────

def _hash(senha: str) -> str:
    return bcrypt.hashpw(senha.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def _confere(senha: str, hash_guardado) -> bool:
    try:
        return bcrypt.checkpw(senha.encode("utf-8"), (hash_guardado or "").encode("utf-8"))
    except Exception:
        return False


def _criar_sessao(cur, user_id) -> str:
    token = secrets.token_urlsafe(32)
    cur.execute("INSERT INTO sessoes_app (token, user_id, expira_em) VALUES (%s, %s, %s)",
                (token, str(user_id), datetime.now(timezone.utc) + timedelta(days=SESSION_DAYS)))
    return token


def _papeis(cur, user_id) -> list:
    cur.execute("SELECT role FROM user_roles WHERE user_id = %s ORDER BY role", (str(user_id),))
    return [r["role"] for r in cur.fetchall()]


def _papel(cur, user_id) -> str:
    papeis = _papeis(cur, user_id)
    if "admin" in papeis:
        return "admin"
    return papeis[0] if papeis else "student"


def _conceder_papel(cur, user_id, papel="student"):
    cur.execute("INSERT INTO user_roles (user_id, role) VALUES (%s, %s) ON CONFLICT DO NOTHING",
                (str(user_id), papel))


def _usuario_por_email(cur, email):
    cur.execute("SELECT * FROM profiles WHERE email = %s", ((email or "").strip().lower(),))
    return cur.fetchone()


def _monta_usuario(cur, linha):
    """Objeto do usuário no formato que o adaptador do front consome."""
    if not linha:
        return None
    papeis = _papeis(cur, linha["id"])
    return {
        "id": str(linha["id"]),
        "email": linha["email"],
        "nome": linha.get("full_name") or "",
        "full_name": linha.get("full_name") or "",
        "papel": "admin" if "admin" in papeis else (papeis[0] if papeis else "student"),
        "roles": papeis,
        "is_admin": "admin" in papeis,
        "avatar_url": linha.get("avatar_url"),
        "precisa_trocar_senha": bool(linha.get("precisa_trocar_senha")),
        "email_confirmed_at": (linha.get("created_at") or datetime.now(timezone.utc)).isoformat(),
        "created_at": (linha.get("created_at") or "").isoformat() if linha.get("created_at") else None,
    }


def usuario_do_token(authorization):
    """Usuário autenticado ou None. Aceita também o token do fluxo antigo.

    Sonda de autenticação NUNCA pode virar 500: erro inesperado vira None (o
    chamador responde 401) e o motivo fica no log.
    """
    if not authorization or not authorization.lower().startswith("bearer "):
        return None
    token = authorization.split(" ", 1)[1].strip()
    if not token:
        return None
    conn = db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """SELECT p.* FROM sessoes_app s JOIN profiles p ON p.id = s.user_id
                   WHERE s.token = %s AND s.expira_em > NOW()""",
                (token,),
            )
            u = cur.fetchone()
            if u:
                return _monta_usuario(cur, u)
            try:
                return _migrar_sessao_antiga(cur, conn, token)
            except Exception as erro:
                logger.warning("token nao resolvido no fluxo antigo: %s", erro)
                return None
    except Exception as erro:
        logger.warning("falha ao validar token: %s", erro)
        return None
    finally:
        conn.close()


def _usuario_por_email_ou_cria(cur, conn, email, nome="", senha_hash=None, papel="student",
                               precisa_trocar=False):
    """Aproveita a aluna do fluxo antigo (WhatsApp): o hash é bcrypt nos dois lados."""
    email = (email or "").strip().lower()
    if "@" not in email:
        return None
    u = _usuario_por_email(cur, email)
    if u:
        _conceder_papel(cur, u["id"], papel)
        if email in ADMIN_EMAILS:
            _conceder_papel(cur, u["id"], "admin")
        return _monta_usuario(cur, u)
    if not senha_hash:
        return None
    cur.execute(
        """INSERT INTO profiles (email, senha_hash, full_name, precisa_trocar_senha)
           VALUES (%s, %s, %s, %s) RETURNING *""",
        (email, senha_hash, nome or "", bool(precisa_trocar)),
    )
    novo = cur.fetchone()
    _conceder_papel(cur, novo["id"], papel)
    if email in ADMIN_EMAILS:
        _conceder_papel(cur, novo["id"], "admin")
    conn.commit()
    logger.info("usuario migrado do fluxo antigo: %s", email)
    return _monta_usuario(cur, novo)


def _buscar_aluna(ident):
    """Aluna do fluxo antigo, em conexão própria (não contamina a transação)."""
    ident = (ident or "").strip().lower()
    try:
        conn = db()
    except Exception:
        return None
    try:
        with conn.cursor() as cur:
            digitos = re.sub(r"\D", "", ident)
            whats = ("55" + digitos) if digitos and not digitos.startswith("55") else digitos
            cur.execute("SELECT * FROM alunas WHERE email = %s OR whatsapp = %s", (ident, whats or ident))
            return cur.fetchone()
    except Exception:
        return None
    finally:
        conn.close()


def _migrar_sessao_antiga(cur, conn, token):
    """Token do fluxo antigo (`sessoes` + `alunas`) vale também no site novo.

    Só migra quem tem email — sem email não há como casar o acesso.
    """
    try:
        cur.execute(
            """SELECT a.* FROM sessoes s JOIN alunas a ON a.id = s.aluna_id
               WHERE s.token = %s AND s.expira_em > now()""",
            (token,),
        )
        aluna = cur.fetchone()
    except Exception as erro:
        logger.info("token antigo nao conferido: %s", str(erro).split("\n")[0][:120])
        return None
    if not aluna:
        return None
    return _usuario_por_email_ou_cria(
        cur, conn, aluna.get("email"), aluna.get("nome") or "",
        aluna.get("senha_hash"), "student", bool(aluna.get("precisa_trocar_senha")),
    )


def _sincronizar_aluna(email, senha_hash):
    try:
        conn = db()
    except Exception:
        return
    try:
        with conn.cursor() as cur:
            cur.execute("UPDATE alunas SET senha_hash = %s, precisa_trocar_senha = false WHERE email = %s",
                        (senha_hash, (email or "").lower()))
        conn.commit()
    except Exception:
        pass
    finally:
        conn.close()


def _exige_usuario(authorization):
    u = usuario_do_token(authorization)
    if not u:
        raise HTTPException(status_code=401, detail="nao autenticado")
    return u


def _exige_admin(authorization):
    u = _exige_usuario(authorization)
    if not u.get("is_admin"):
        raise HTTPException(status_code=403, detail="acesso negado")
    return u


def _sessao_json(token, u):
    """Formato novo + os campos que o fluxo antigo devolvia."""
    return {
        "token": token,
        "usuario": u,
        "user": u,
        "session": {"access_token": token, "token_type": "bearer", "user": u},
        "nome": u["nome"],
        "precisa_trocar_senha": u["precisa_trocar_senha"],
    }


# ── autenticação ─────────────────────────────────────────────────────────────

class CadastroIn(BaseModel):
    email: str
    senha: str = ""
    password: str = ""
    nome: str = ""
    full_name: str = ""


class LoginIn(BaseModel):
    email: str = ""
    identificador: str = ""
    senha: str = ""
    password: str = ""


class TrocarSenhaIn(BaseModel):
    senha_nova: str = ""
    new_password: str = ""
    senha_atual: str = ""


@router.post("/auth/cadastro")
def cadastro(dados: CadastroIn):
    email = (dados.email or "").strip().lower()
    senha = dados.senha or dados.password
    nome = dados.nome or dados.full_name or ""
    if "@" not in email or len(senha or "") < 6:
        raise HTTPException(status_code=422, detail="informe um email valido e senha com 6+ caracteres")
    conn = db()
    try:
        with conn.cursor() as cur:
            if _usuario_por_email(cur, email):
                raise HTTPException(status_code=409, detail="email ja cadastrado")
            cur.execute(
                """INSERT INTO profiles (email, senha_hash, full_name) VALUES (%s, %s, %s) RETURNING *""",
                (email, _hash(senha), nome),
            )
            linha = cur.fetchone()
            # admin: email do dono (ADMIN_EMAILS) ou o primeiro usuário do sistema
            cur.execute("SELECT 1 FROM user_roles WHERE role = 'admin' LIMIT 1")
            papel = "admin" if (not cur.fetchone() or email in ADMIN_EMAILS) else "student"
            _conceder_papel(cur, linha["id"], papel)
            token = _criar_sessao(cur, linha["id"])
            liberados = _liberar_pendentes(cur, email, linha["id"])
            u = _monta_usuario(cur, linha)
        conn.commit()
        logger.info("cadastro: %s papel=%s pendentes_liberados=%s", email, papel, liberados)
        return _sessao_json(token, u)
    finally:
        conn.close()


@router.post("/auth/login")
def login(dados: LoginIn):
    """Serve o site novo (`email`) e o fluxo antigo (`identificador`: email ou telefone)."""
    ident = (dados.email or dados.identificador or "").strip().lower()
    senha = dados.senha or dados.password
    if not ident or not senha:
        raise HTTPException(status_code=422, detail="informe email e senha")
    conn = db()
    try:
        with conn.cursor() as cur:
            linha = _usuario_por_email(cur, ident)
            if not (linha and _confere(senha, linha.get("senha_hash"))):
                linha = None
                aluna = _buscar_aluna(ident)
                if aluna and _confere(senha, aluna.get("senha_hash")):
                    if not aluna.get("email"):
                        raise HTTPException(status_code=409,
                                            detail="cadastro antigo sem email: refaca o cadastro no site")
                    _usuario_por_email_ou_cria(cur, conn, aluna.get("email"), aluna.get("nome") or "",
                                               aluna.get("senha_hash"), "student",
                                               bool(aluna.get("precisa_trocar_senha")))
                    linha = _usuario_por_email(cur, (aluna.get("email") or "").lower())
            if not linha:
                raise HTTPException(status_code=401, detail="email ou senha invalidos")
            if (linha.get("email") or "").lower() in ADMIN_EMAILS:
                _conceder_papel(cur, linha["id"], "admin")
            token = _criar_sessao(cur, linha["id"])
            liberados = _liberar_pendentes(cur, linha["email"], linha["id"])
            u = _monta_usuario(cur, linha)
        conn.commit()
        logger.info("login ok: %s pendentes_liberados=%s", u["email"], liberados)
        return _sessao_json(token, u)
    finally:
        conn.close()


@router.post("/auth/logout")
def logout(authorization: str = Header(None)):
    u = _exige_usuario(authorization)
    token = authorization.split(" ", 1)[1].strip()
    conn = db()
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM sessoes_app WHERE token = %s", (token,))
        conn.commit()
        return {"ok": True, "usuario": u["id"]}
    finally:
        conn.close()


@router.get("/auth/me")
@router.get("/auth/user")
def me(authorization: str = Header(None)):
    u = _exige_usuario(authorization)
    return {"usuario": u, "user": u}


@router.post("/auth/trocar-senha")
def trocar_senha(dados: TrocarSenhaIn, authorization: str = Header(None)):
    u = _exige_usuario(authorization)
    nova = dados.senha_nova or dados.new_password
    # senha_atual é opcional: no primeiro acesso (senha temporária) basta o token
    if dados.senha_atual:
        conn0 = db()
        try:
            with conn0.cursor() as c0:
                c0.execute("SELECT senha_hash FROM profiles WHERE id = %s", (u["id"],))
                if not _confere(dados.senha_atual, (c0.fetchone() or {}).get("senha_hash")):
                    raise HTTPException(status_code=401, detail="senha atual incorreta")
        finally:
            conn0.close()
    if len(nova or "") < 6:
        raise HTTPException(status_code=422, detail="senha nova curta (min 6)")
    novo = _hash(nova)
    conn = db()
    try:
        with conn.cursor() as cur:
            cur.execute("""UPDATE profiles SET senha_hash = %s, precisa_trocar_senha = FALSE,
                                  updated_at = NOW() WHERE id = %s""", (novo, u["id"]))
        conn.commit()
    finally:
        conn.close()
    _sincronizar_aluna(u["email"], novo)
    return {"ok": True}


# ── liberação de acesso pelo email (OnProfit / Cakto) ────────────────────────

def _liberar_pendentes(cur, email, user_id):
    cur.execute("SELECT course_id FROM acessos_pendentes WHERE email = %s", ((email or "").lower(),))
    liberados = [l["course_id"] for l in cur.fetchall()]
    for cid in liberados:
        cur.execute("INSERT INTO enrollments (user_id, course_id) VALUES (%s, %s) ON CONFLICT DO NOTHING",
                    (str(user_id), str(cid)))
    if liberados:
        cur.execute("DELETE FROM acessos_pendentes WHERE email = %s", ((email or "").lower(),))
    return len(liberados)


def aplicar_compra(info):
    """Decisão do webhook -> banco. Libera/revoga o curso pelo EMAIL do comprador."""
    email = (info.get("email") or "").strip().lower()
    decisao = info.get("decisao")
    if not email or decisao not in ("liberar", "revogar"):
        return {"aplicado": False, "motivo": "sem email ou decisao ignorada"}

    chaves = [str(c) for c in (info.get("oferta"), info.get("produto_hash"), info.get("produto_id")) if c]
    if not chaves:
        return {"aplicado": False, "motivo": "payload sem oferta/produto identificavel"}

    conn = db()
    try:
        with conn.cursor() as cur:
            course_ids = []
            for chave in chaves:
                cur.execute("SELECT course_id FROM mapa_ofertas WHERE oferta = %s", (chave,))
                course_ids += [str(l["course_id"]) for l in cur.fetchall()]
            if not course_ids:
                # Sem mapa cadastrado: se existe UM UNICO curso publicado, a compra vale para ele.
                # Assim o gateway funciona sem depender do offer_hash quando so ha um curso.
                cur.execute("SELECT id FROM courses WHERE is_published "
                            "ORDER BY position, created_at LIMIT 2")
                publicados = cur.fetchall()
                if len(publicados) == 1:
                    course_ids = [str(publicados[0]["id"])]
                    logger.info("compra %s: sem mapa; aplicando no unico curso publicado %s",
                                decisao, course_ids[0])
                else:
                    logger.warning("compra %s: oferta(s) %s sem mapa -> curso (%d curso(s) publicado(s))",
                                   decisao, chaves, len(publicados))
                    return {"aplicado": False, "motivo": "oferta sem mapa para curso",
                            "ofertas": chaves, "cursos_publicados": len(publicados)}

            linha = _usuario_por_email(cur, email)
            if decisao == "liberar":
                if linha:
                    for cid in course_ids:
                        cur.execute("INSERT INTO enrollments (user_id, course_id) VALUES (%s, %s) "
                                    "ON CONFLICT DO NOTHING", (str(linha["id"]), cid))
                else:
                    for cid in course_ids:
                        cur.execute("""INSERT INTO acessos_pendentes (email, course_id, origem, pedido_id)
                                       VALUES (%s, %s, %s, %s) ON CONFLICT DO NOTHING""",
                                    (email, cid, info.get("origem") or "webhook", str(info.get("pedido") or "")))
            else:
                if linha:
                    for cid in course_ids:
                        cur.execute("DELETE FROM enrollments WHERE user_id = %s AND course_id = %s",
                                    (str(linha["id"]), cid))
                for cid in course_ids:
                    cur.execute("DELETE FROM acessos_pendentes WHERE email = %s AND course_id = %s",
                                (email, cid))
        conn.commit()
        logger.info("compra %s: email=%s cursos=%s usuario=%s", decisao, email, course_ids,
                    "existia" if linha else "novo (pendente)")
        return {"aplicado": True, "cursos": course_ids, "usuario_existia": bool(linha)}
    finally:
        conn.close()


# ── /api/db/{tabela}: o "REST do Supabase" que o front já sabe chamar ────────

def _escopo_aluno(tabela, usuario):
    """WHERE extra que limita o que um aluno (não-admin) enxerga."""
    me = usuario["id"]
    if tabela == "profiles":
        return ["id = %s"], [me]
    if tabela == "user_roles":
        return ["user_id = %s"], [me]
    if tabela == "courses":
        # catálogo público OU curso que ele comprou (comprado vale mesmo fora do catálogo)
        return ["((is_published AND show_in_catalog) OR id IN "
                "(SELECT course_id FROM enrollments WHERE user_id = %s))"], [me]
    if tabela == "modules":
        # curso liberado para todos dispensa compra; o resto continua so para quem tem matricula
        return ["(course_id IN (SELECT id FROM courses WHERE liberado_para_todos) OR "
                "course_id IN (SELECT course_id FROM enrollments WHERE user_id = %s))"], [me]
    if tabela == "lessons":
        return ["module_id IN (SELECT m.id FROM modules m WHERE "
                "m.course_id IN (SELECT id FROM courses WHERE liberado_para_todos) OR "
                "m.course_id IN (SELECT course_id FROM enrollments WHERE user_id = %s))"], [me]
    if tabela == "enrollments":
        return ["user_id = %s"], [me]
    if tabela == "lesson_progress":
        return ["user_id = %s"], [me]
    if tabela == "banners":
        # banner desligado é rascunho do admin: aluno só vê os ligados
        return ["ativo = TRUE"], []
    return ["FALSE"], []


def _filtros(request, cfg):
    """filter[col]=v | eq[col]=v | in[col]=a,b -> WHERE parametrizado."""
    where, params = [], []
    for chave, valor in request.query_params.items():
        prefixo = next((p for p in ("filter[", "eq[", "in[") if chave.startswith(p)), None)
        if not prefixo:
            continue
        col = chave[chave.index("[") + 1:chave.rindex("]")]
        if not ID_RE.match(col):
            raise HTTPException(status_code=400, detail="campo invalido: %s" % col)
        if prefixo == "in[":
            valores = [v for v in str(valor).split(",") if v != ""]
            if not valores:
                where.append("FALSE")
                continue
            where.append('"%s" = ANY(%%s)' % col)
            params.append(valores)
            continue
        where.append('"%s" = %%s' % col)
        params.append(valor)
    return where, params


def _embutir(cur, tabela, linhas, embed):
    """select('*, lessons(*)') -> anexa a lista relacionada em cada linha."""
    relacoes = EMBEDS.get(tabela) or {}
    for nome in [e.strip() for e in (embed or "").split(",") if e.strip()]:
        rel = relacoes.get(nome)
        if not rel:
            continue
        destino, chave_local = rel
        for linha in linhas:
            cur.execute('SELECT * FROM %s WHERE "%s" = %%s' % (destino, chave_local), (str(linha["id"]),))
            linha[nome] = cur.fetchall()
    return linhas


def _filtro_obrigatorio(where):
    if not where:
        raise HTTPException(status_code=400, detail="operacao sem filtro recusada")


def _normalizar_materiais(valor):
    """Materiais da aula vêm como lista de {label, url} e viram texto JSON.

    Aula só de material é legítima: `youtube_url` vazio + materiais preenchidos.
    Qualquer coisa estranha vira lista vazia, nunca quebra a gravação.
    """
    if valor is None:
        return "[]"
    itens = valor
    if isinstance(valor, str):
        try:
            itens = json.loads(valor or "[]")
        except Exception:
            return "[]"
    if not isinstance(itens, list):
        return "[]"
    limpos = []
    for item in itens:
        if not isinstance(item, dict):
            continue
        url = str(item.get("url") or "").strip()
        if not url:
            continue
        limpos.append({"label": str(item.get("label") or "").strip()[:120],
                       "url": url[:1000]})
    return json.dumps(limpos, ensure_ascii=False)


@router.api_route("/api/db/{tabela}", methods=["GET", "POST", "PATCH", "PUT", "DELETE"])
async def api_db(tabela: str, request: Request, authorization: str = Header(None)):
    usuario = _exige_usuario(authorization)
    if tabela not in TABELAS:
        raise HTTPException(status_code=404, detail="tabela nao permitida")
    cfg = TABELAS[tabela]
    real = cfg["tabela"]
    admin = bool(usuario.get("is_admin"))
    metodo = request.method

    conn = db()
    try:
        with conn.cursor() as cur:
            # ── leitura ──
            if metodo == "GET":
                where, params = _filtros(request, cfg)
                if not admin:
                    w, p = _escopo_aluno(tabela, usuario)
                    where += w
                    params += p
                sql = "SELECT * FROM %s" % real
                if where:
                    sql += " WHERE " + " AND ".join(where)
                ordem = request.query_params.get("order")
                if ordem:
                    col, _, dirn = ordem.partition(".")
                    if ID_RE.match(col):
                        sql += ' ORDER BY "%s" %s' % (col, "DESC" if dirn.lower() == "desc" else "ASC")
                limite = request.query_params.get("limit")
                if limite and str(limite).isdigit():
                    sql += " LIMIT %d" % min(int(limite), 500)
                cur.execute(sql, params)
                linhas = cur.fetchall()
                return {"dados": _embutir(cur, tabela, linhas, request.query_params.get("embed"))}

            if metodo == "DELETE":
                linhas_corpo = [{}]          # DELETE não tem corpo
            else:
                try:
                    corpo = await request.json()
                except Exception:
                    corpo = {}
                linhas_corpo = corpo if isinstance(corpo, list) else [corpo]
                if not linhas_corpo or not all(isinstance(l, dict) for l in linhas_corpo):
                    raise HTTPException(status_code=400, detail="corpo invalido")

            on_conflict = request.query_params.get("on_conflict")
            if on_conflict:
                on_conflict = ",".join(c.strip() for c in on_conflict.split(",") if ID_RE.match(c.strip()))
                if not on_conflict:
                    raise HTTPException(status_code=400, detail="on_conflict invalido")

            # ── escrita ──
            forcar_update = False
            if not admin:
                if tabela == "profiles":
                    # aluno só ajusta o PRÓPRIO perfil: nunca cria conta nem troca email/senha
                    forcar_update = True
                    for linha in linhas_corpo:
                        linha["id"] = usuario["id"]
                        for proibido in ("email", "senha_hash", "created_at"):
                            linha.pop(proibido, None)
                elif tabela == "lesson_progress":
                    for linha in linhas_corpo:
                        linha["user_id"] = usuario["id"]      # nunca aceita outro dono
                else:
                    raise HTTPException(status_code=403, detail="somente admin")

            def _padroes(linha):
                if tabela == "courses":
                    if not (linha.get("title") or "").strip():
                        raise HTTPException(status_code=422, detail="curso sem titulo")
                    if not (linha.get("slug") or "").strip():
                        base = re.sub(r"[^a-z0-9]+", "-", linha["title"].lower()).strip("-")[:40] or "curso"
                        linha["slug"] = "%s-%s" % (base, secrets.token_hex(3))
                if tabela == "lessons":
                    if not (linha.get("title") or "").strip():
                        raise HTTPException(status_code=422, detail="aula sem titulo")
                    # só mexe no que veio no corpo: PATCH de um campo não pode apagar o vídeo
                    if "youtube_url" in linha:
                        linha["youtube_url"] = linha.get("youtube_url") or ""
                    if "materials" in linha:
                        linha["materials"] = _normalizar_materiais(linha["materials"])
                return linha

            gravadas = []
            if metodo in ("POST", "PUT"):
                for linha in linhas_corpo:
                    linha = _padroes(linha)
                    cols = [c for c in linha.keys() if ID_RE.match(c)]
                    if not cols:
                        raise HTTPException(status_code=400, detail="nada para gravar")
                    if forcar_update:      # upsert do próprio perfil = update
                        sets = ", ".join('"%s" = %%s' % c for c in cols if c != "id")
                        vals = [linha[c] for c in cols if c != "id"]
                        if not sets:
                            raise HTTPException(status_code=400, detail="nada para atualizar")
                        cur.execute('UPDATE profiles SET %s WHERE id = %%s RETURNING *' % sets,
                                    vals + [usuario["id"]])
                        gravadas.append(cur.fetchone())
                        continue
                    sql = 'INSERT INTO %s (%s) VALUES (%s)' % (
                        real, ", ".join('"%s"' % c for c in cols), ", ".join(["%s"] * len(cols)))
                    if on_conflict:
                        atualizaveis = ", ".join('"%s" = EXCLUDED."%s"' % (c, c) for c in cols
                                                if c not in on_conflict.split(","))
                        sql += " ON CONFLICT (%s) DO UPDATE SET %s" % (
                            on_conflict, atualizaveis or '"id" = %s."id"' % real)
                    sql += " RETURNING *"
                    cur.execute(sql, [linha[c] for c in cols])
                    gravadas.append(cur.fetchone())

            elif metodo == "PATCH":
                where, params = _filtros(request, cfg)
                if not admin:
                    w, p = _escopo_aluno(tabela, usuario)
                    where += w
                    params += p
                _filtro_obrigatorio(where)
                for linha in linhas_corpo:
                    linha = _padroes(linha)
                    proibidos = ("id", "senha_hash") if admin else ("id", "senha_hash", "email")
                    cols = [c for c in linha.keys() if ID_RE.match(c) and c not in proibidos]
                    if not cols:
                        raise HTTPException(status_code=400, detail="nada para atualizar")
                    sets = ['"%s" = %%s' % c for c in cols]
                    vals = [linha[c] for c in cols]
                    if tabela in TEM_UPDATED_AT:
                        sets.append('"updated_at" = NOW()')
                    sql = "UPDATE %s SET %s WHERE %s RETURNING *" % (real, ", ".join(sets), " AND ".join(where))
                    cur.execute(sql, vals + params)
                    gravadas.append(cur.fetchone())

            else:  # DELETE
                if not admin and tabela not in APAGAR_ALUNO:
                    raise HTTPException(status_code=403, detail="somente admin")
                where, params = _filtros(request, cfg)
                if not admin:
                    w, p = _escopo_aluno(tabela, usuario)
                    where += w
                    params += p
                _filtro_obrigatorio(where)
                cur.execute("DELETE FROM %s WHERE %s" % (real, " AND ".join(where)), params)
                gravadas = [{"removidos": cur.rowcount}]
        conn.commit()
        if metodo == "POST":
            return {"dados": gravadas[0] if len(gravadas) == 1 else gravadas}
        return {"dados": gravadas[0] if len(gravadas) == 1 else gravadas}
    except psycopg2.errors.UniqueViolation as erro:
        conn.rollback()
        raise HTTPException(status_code=409, detail="registro duplicado (%s)" % str(erro).split("\n")[0][:120])
    except HTTPException:
        conn.rollback()
        raise
    except Exception as erro:
        conn.rollback()
        logger.exception("erro em /api/db/%s", tabela)
        raise HTTPException(status_code=500, detail="erro interno: %s" % str(erro)[:150])
    finally:
        conn.close()


# ── mídia no banco (bytea) ───────────────────────────────────────────────────

_MAGIC = [(b"\xff\xd8\xff", "image/jpeg"), (b"\x89PNG", "image/png"),
          (b"GIF8", "image/gif"), (b"RIFF", "image/webp")]

ALVOS_MIDIA = {
    "course":  ("courses", "cover_url"),
    "module":  ("modules", "cover_url"),
    "lesson":  ("lessons", "image_url"),
    "banner":  ("banners", "imagem_url"),
    "profile": ("profiles", "avatar_url"),
    "usuario": ("profiles", "avatar_url"),
}


def _mime(dados: bytes, informado=None):
    for magic, m in _MAGIC:
        if dados.startswith(magic):
            return m
    return informado or "application/octet-stream"


@router.post("/api/media/upload")
async def media_upload(tipo: str = Form(...), id: str = Form(...),
                       arquivo: UploadFile = File(None), file: UploadFile = File(None),
                       authorization: str = Header(None)):
    usuario = _exige_usuario(authorization)
    alvo = ALVOS_MIDIA.get((tipo or "").lower())
    if not alvo:
        raise HTTPException(status_code=400, detail="tipo invalido (use course|module|lesson|banner|profile)")
    tabela, coluna = alvo
    if not usuario.get("is_admin") and not (tabela == "profiles" and str(id) == usuario["id"]):
        raise HTTPException(status_code=403, detail="somente admin")
    upload = arquivo or file
    if not upload:
        raise HTTPException(status_code=422, detail="nenhum arquivo enviado")
    dados = await upload.read()
    if not dados:
        raise HTTPException(status_code=422, detail="arquivo vazio")
    if len(dados) > MAX_BYTES:
        raise HTTPException(status_code=413, detail="arquivo maior que %d MB" % (MAX_BYTES // 1024 // 1024))
    try:
        UUID(str(id))
    except Exception:
        raise HTTPException(status_code=422, detail="id invalido")
    mime = _mime(dados, upload.content_type)
    # A URL carrega a versao do envio. Sem isso a imagem fica gravada na MESMA URL e o
    # navegador segue mostrando a antiga por 24h (parecia que a troca de capa nao funcionava).
    url = "/api/media/%s/%s?v=%d" % (tipo.lower(), id, int(time.time()))
    conn = db()
    try:
        with conn.cursor() as cur:
            cur.execute("""INSERT INTO midias (tipo, ref_id, bytes, mime, atualizado_em)
                           VALUES (%s, %s, %s, %s, NOW())
                           ON CONFLICT (tipo, ref_id) DO UPDATE
                           SET bytes = EXCLUDED.bytes, mime = EXCLUDED.mime, atualizado_em = NOW()""",
                        (tipo.lower(), str(id), psycopg2.Binary(dados), mime))
            cur.execute('UPDATE %s SET "%s" = %%s, updated_at = NOW() WHERE id = %%s' % (tabela, coluna),
                        (url, str(id)))
            vinculado = bool(cur.rowcount)
        conn.commit()
        if not vinculado:
            # Imagem escolhida antes de o curso/modulo/aula existir (criacao no painel):
            # o arquivo fica guardado em `midias` e passa a ser servido por /api/media/{tipo}/{id}.
            logger.info("midia %s %s sem registro correspondente (criacao em andamento)", tipo, id)
        logger.info("midia gravada: %s %s (%d bytes, %s)", tipo, id, len(dados), mime)
        return {"ok": True, "url": url, "bytes": len(dados), "mime": mime, "vinculado": vinculado}
    finally:
        conn.close()


@router.get("/api/media/{tipo}/{id}")
def media_get(tipo: str, id: str, v: str = Query(None)):
    conn = db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT bytes, mime FROM midias WHERE tipo = %s AND ref_id = %s",
                        ((tipo or "").lower(), id))
            linha = cur.fetchone()
    except Exception:
        linha = None
    finally:
        conn.close()
    if not linha or not linha["bytes"]:
        raise HTTPException(status_code=404, detail="sem imagem")
    # URL com versao pode ser guardada para sempre (cada envio muda a URL).
    # URL antiga (sem versao) precisa revalidar, senao a troca nao aparece na tela.
    cache = "public, max-age=31536000, immutable" if v else "public, max-age=0, must-revalidate"
    return Response(content=bytes(linha["bytes"]), media_type=linha["mime"] or "image/jpeg",
                    headers={"Cache-Control": cache})


@router.delete("/api/media/{tipo}/{id}")
def media_apagar(tipo: str, id: str, authorization: str = Header(None)):
    """Tira a imagem do banco e limpa a coluna que apontava pra ela."""
    usuario = _exige_usuario(authorization)
    alvo = ALVOS_MIDIA.get((tipo or "").lower())
    if not alvo:
        raise HTTPException(status_code=400, detail="tipo invalido")
    tabela, coluna = alvo
    if not usuario.get("is_admin") and not (tabela == "profiles" and str(id) == usuario["id"]):
        raise HTTPException(status_code=403, detail="somente admin")
    conn = db()
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM midias WHERE tipo = %s AND ref_id = %s", ((tipo or "").lower(), id))
            removidas = cur.rowcount
            cur.execute('UPDATE %s SET "%s" = NULL, updated_at = NOW() WHERE id = %%s' % (tabela, coluna), (id,))
        conn.commit()
        return {"ok": True, "removidas": removidas}
    finally:
        conn.close()


# ── admin ────────────────────────────────────────────────────────────────────

class MapaIn(BaseModel):
    oferta: str
    course_id: str


@router.post("/admin/mapa-ofertas")
def mapa_ofertas(dados: MapaIn, authorization: str = Header(None)):
    """Liga o hash/id da oferta (OnProfit/Cakto) ao curso que ela libera."""
    _exige_admin(authorization)
    try:
        UUID(dados.course_id)
    except Exception:
        raise HTTPException(status_code=422, detail="course_id invalido")
    conn = db()
    try:
        with conn.cursor() as cur:
            cur.execute("""INSERT INTO mapa_ofertas (oferta, course_id) VALUES (%s, %s)
                           ON CONFLICT (oferta) DO UPDATE SET course_id = EXCLUDED.course_id
                           RETURNING oferta, course_id""", (dados.oferta.strip(), dados.course_id))
            linha = cur.fetchone()
            cur.execute("SELECT title FROM courses WHERE id = %s", (dados.course_id,))
            curso = cur.fetchone()
        conn.commit()
        return {"ok": True, "mapa": {"oferta": linha["oferta"], "course_id": str(linha["course_id"]),
                                     "curso": (curso or {}).get("title")}}
    finally:
        conn.close()


@router.get("/admin/mapa-ofertas")
def mapa_ofertas_listar(authorization: str = Header(None)):
    _exige_admin(authorization)
    conn = db()
    try:
        with conn.cursor() as cur:
            cur.execute("""SELECT m.oferta, m.course_id, c.title FROM mapa_ofertas m
                           LEFT JOIN courses c ON c.id = m.course_id ORDER BY m.criado_em""")
            return {"mapa": cur.fetchall()}
    finally:
        conn.close()


@router.get("/admin/pendentes")
def admin_pendentes(authorization: str = Header(None)):
    """Compras aprovadas de quem ainda não tem conta (entra quando se cadastrar)."""
    _exige_admin(authorization)
    conn = db()
    try:
        with conn.cursor() as cur:
            cur.execute("""SELECT a.email, a.course_id, c.title, a.origem, a.criado_em
                           FROM acessos_pendentes a LEFT JOIN courses c ON c.id = a.course_id
                           ORDER BY a.criado_em DESC""")
            return {"pendentes": cur.fetchall()}
    finally:
        conn.close()


@router.get("/admin/usuarios")
def admin_usuarios(authorization: str = Header(None)):
    _exige_admin(authorization)
    conn = db()
    try:
        with conn.cursor() as cur:
            cur.execute("""SELECT p.id, p.email, p.full_name, p.created_at,
                                  COALESCE((SELECT string_agg(r.role, ',') FROM user_roles r
                                            WHERE r.user_id = p.id), 'student') AS papeis,
                                  (SELECT COUNT(*) FROM enrollments e WHERE e.user_id = p.id) AS cursos
                           FROM profiles p ORDER BY p.created_at DESC""")
            return {"usuarios": cur.fetchall()}
    finally:
        conn.close()


@router.post("/admin/conceder-admin")
def conceder_admin(email: str = Query(...), key: str = Query(...)):
    """Recuperação de acesso: promove `email` a admin usando ADMIN_SECRET.

    Mesmo segredo dos /admin antigos do backend. Existe pro caso "trancou o acesso e
    não há nenhum admin no banco" — sem isso só sobraria mexer no banco na mão.
    """
    if not ADMIN_SECRET or key != ADMIN_SECRET:
        raise HTTPException(status_code=403, detail="acesso negado")
    conn = db()
    try:
        with conn.cursor() as cur:
            linha = _usuario_por_email(cur, email)
            if not linha:
                raise HTTPException(status_code=404, detail="nao existe conta com esse email")
            _conceder_papel(cur, linha["id"], "admin")
        conn.commit()
        logger.info("papel admin concedido (recuperacao): %s", (email or "").lower())
        return {"ok": True, "email": (email or "").lower(), "papel": "admin"}
    finally:
        conn.close()


@router.post("/admin/criar-tabelas")
def admin_criar_tabelas(authorization: str = Header(None)):
    _exige_admin(authorization)
    criar_tabelas()
    return {"ok": True}
