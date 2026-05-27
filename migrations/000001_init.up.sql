CREATE SCHEMA auth;

CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS citext;

CREATE TABLE auth.users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

  status TEXT NOT NULL DEFAULT 'active'
  CHECK (status IN (
          'active',
          'blocked'
        )),
  
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  deleted_at TIMESTAMPTZ
);

CREATE TABLE auth.user_profile(
  user_id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,

  first_name VARCHAR(100),
  middle_name VARCHAR(100),
  last_name VARCHAR(100),
  phone_number VARCHAR(20)
    CHECK (phone_number ~ '^\+[1-9]\d{9,14}$'),
  avatar_url TEXT,
  display_name VARCHAR(100),

  timezone TEXT,

  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE auth.password_credentials(
  user_id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,

  email CITEXT NOT NULL UNIQUE,
  password_hash text NOT NULL,

  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);