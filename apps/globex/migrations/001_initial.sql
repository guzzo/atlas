CREATE TABLE IF NOT EXISTS challenges (
 nonce text PRIMARY KEY,
 audience text NOT NULL,
 action text NOT NULL,
 resource text NOT NULL,
 issued_at bigint NOT NULL,
 expires_at bigint NOT NULL,
 consumed boolean NOT NULL DEFAULT false
);
CREATE TABLE IF NOT EXISTS executions (
 id text PRIMARY KEY,
 nonce text NOT NULL UNIQUE REFERENCES challenges(nonce),
 request_id text NOT NULL,
 capability_id text NOT NULL UNIQUE,
 request_digest text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS receipts (
 id text PRIMARY KEY,
 document jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS outbox (
 id bigserial PRIMARY KEY,
 receipt_id text NOT NULL UNIQUE REFERENCES receipts(id),
 topic text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now()
);
