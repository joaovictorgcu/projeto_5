-- Schema SQL do Keyflow MVP
-- Cofre de Senhas Colaborativo para Pequenas Equipes

CREATE TABLE IF NOT EXISTS organizations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name VARCHAR(120) NOT NULL,
    invite_code VARCHAR(36) UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(150) UNIQUE NOT NULL,
    password_hash VARCHAR(200) NOT NULL,
    org_id INTEGER REFERENCES organizations(id),
    role VARCHAR(20) DEFAULT 'member',
    is_active_member BOOLEAN DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER NOT NULL REFERENCES organizations(id),
    name VARCHAR(120) NOT NULL,
    login VARCHAR(200) NOT NULL,
    encrypted_password TEXT NOT NULL,
    notes TEXT DEFAULT '',
    created_by INTEGER NOT NULL REFERENCES users(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS credential_permissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    credential_id INTEGER NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id),
    can_view_password BOOLEAN DEFAULT 0
);

CREATE TABLE IF NOT EXISTS access_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    credential_id INTEGER NOT NULL REFERENCES credentials(id),
    action VARCHAR(50) NOT NULL,
    accessed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
