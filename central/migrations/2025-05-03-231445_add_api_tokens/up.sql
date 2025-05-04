CREATE TABLE api_tokens (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    owner TEXT NOT NULL,
    description TEXT NOT NULL,
    validations_per_day INTEGER NOT NULL,
    validations_per_hour INTEGER NOT NULL
)
