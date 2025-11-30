CREATE TABLE request_meta (
    user_agent TEXT NOT NULL,
    mod_id TEXT NOT NULL,
    UNIQUE(user_agent, mod_id)
);

CREATE TABLE token_logs (
    ip BLOB(16) NOT NULL,
    timestamp BIGINTEGER NOT NULL,
    time_taken_ms INTEGER NOT NULL,
    meta_id INTEGER NOT NULL
);
