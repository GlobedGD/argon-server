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
