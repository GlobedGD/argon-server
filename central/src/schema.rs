// @generated automatically by Diesel CLI.

diesel::table! {
    api_tokens (id) {
        id -> Integer,
        name -> Text,
        owner -> Text,
        description -> Text,
        validations_per_day -> Integer,
        validations_per_hour -> Integer,
    }
}

diesel::table! {
    request_meta (rowid) {
        rowid -> Integer,
        user_agent -> Text,
        mod_id -> Text,
    }
}

diesel::table! {
    token_logs (rowid) {
        rowid -> Integer,
        ip -> Binary,
        timestamp -> BigInt,
        time_taken_ms -> Integer,
        meta_id -> Integer,
    }
}

diesel::allow_tables_to_appear_in_same_query!(api_tokens, request_meta, token_logs,);
