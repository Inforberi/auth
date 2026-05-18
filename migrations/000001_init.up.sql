CREATE SCHEMA auth;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE auth.users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

  status TEXT NOT NULL DEFAULT "active"
  CHECK (status IN (
          "active",
          "blocked"
        )),
  
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  deleted_at TIMESTAMPTZ,
)