-- Esquema de MiniGestor Documental. Es el mismo en ambos modos: la diferencia
-- entre v1 y v2 está en el código que lo usa, no en las tablas, para que el
-- "antes/después" compare implementación y no modelos de datos distintos.

CREATE TABLE IF NOT EXISTS users (
    id            BIGSERIAL PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'user',
    totp_secret   TEXT,
    totp_enabled  BOOLEAN NOT NULL DEFAULT FALSE,
    failed_logins INTEGER NOT NULL DEFAULT 0,
    locked_until  TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS documents (
    id             BIGSERIAL PRIMARY KEY,
    owner_id       BIGINT NOT NULL REFERENCES users(id),
    title          TEXT NOT NULL,
    filename       TEXT NOT NULL,
    mime           TEXT NOT NULL,
    size_bytes     BIGINT NOT NULL,
    -- v1: ruta en claro dentro del volumen. v2: identificador opaco cifrado.
    storage_ref    TEXT NOT NULL,
    classification TEXT NOT NULL DEFAULT 'interno',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Solo la usa el modo endurecido: sesión con estado en el servidor.
CREATE TABLE IF NOT EXISTS sessions (
    sid        TEXT PRIMARY KEY,
    username   TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id      BIGSERIAL PRIMARY KEY,
    ts      TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor   TEXT,
    action  TEXT NOT NULL,
    target  TEXT,
    outcome TEXT NOT NULL,
    detail  TEXT
);

CREATE INDEX IF NOT EXISTS documents_owner_idx ON documents(owner_id);
CREATE INDEX IF NOT EXISTS sessions_expiry_idx ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS audit_ts_idx ON audit_log(ts DESC);
