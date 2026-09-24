CREATE TABLE IF NOT EXISTS organizations (
 id text PRIMARY KEY,
 active_policy text NOT NULL DEFAULT '',
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS root_keys (
 org_id text NOT NULL REFERENCES organizations(id),
 id text NOT NULL,
 public_key text NOT NULL,
 revoked boolean NOT NULL DEFAULT false,
 PRIMARY KEY (org_id,id)
);
CREATE TABLE IF NOT EXISTS records (
 org_id text NOT NULL REFERENCES organizations(id),
 kind text NOT NULL,
 id text NOT NULL,
 document jsonb NOT NULL,
 revoked boolean NOT NULL DEFAULT false,
 created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY (org_id,kind,id)
);
CREATE TABLE IF NOT EXISTS receipts (
 id text PRIMARY KEY,
 org_id text NOT NULL REFERENCES organizations(id),
 document jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS outbox (
 id bigserial PRIMARY KEY,
 org_id text NOT NULL,
 topic text NOT NULL,
 object_id text NOT NULL,
 evidence_digest text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS outbox_org_id ON outbox(org_id,id);
