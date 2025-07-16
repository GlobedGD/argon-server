# Server-Side API

This describes the API that should be used by the **server** of a mod that wants to integrate Argon. For a quick example on how to correctly do auth, check the [Argon README](https://github.com/GlobedGD/argon), this document describes some exact details about the API.

All endpoints here respond with status code 200 and a JSON object, unless critical errors happened or you are rate limited. You should **always** check the status code of the request - if it's not 200 then the data is not a JSON object and could be an error message. A response with code 429 will be returned if you are rate limited - check [Rate Limits](#rate-limits) section for more information.

A more efficient WebSockets API is also available, see [GET /v1/ws](#get-v1ws) for more information.

Quick navigation:
* [Rate limits](#rate-limits)
* [GET /v1/status](#get-v1status) - querying server state
* [GET /v1/validation/check](#get-v1validationcheck) - verifying a user's token
* [POST /v1/validation/check-many](#post-v1validationcheck-many) - verifying tokens of up to 50 users
* [GET /v1/validation/check-strong](#get-v1validationcheck-strong) - verifying a user's token, optionally their user ID and username
* [POST /v1/validation/check-strong-many](#post-v1validationcheck-strong-many) - strong verification of tokens of up to 50 users
* [POST /v1/validation/check-data-many](#post-v1validationcheck-data-many) - validate a token and retrieve user data (up to 50 users in 1 request)
* [GET /v1/ws](#get-v1ws) - Websockets based API

# Rate limits

To prevent abuse, rate limits apply if you are using our official server (https://argon.globed.dev). If you exceed either of the following limits, you will be temporarily blocked and will receive an HTTP 429 in response:

* 10000 token validations in one day
* 750 validations in one hour

This effectively allows you to authorize ~7 users per minute, which should be enough for most small to medium sized mods (though these limits are subject to change). As described in the [Best Practices](https://github.com/GlobedGD/argon/blob/main/best-practices.md) guide, it is recommended that your server also has its own kind of session tokens, which can often reduce the requests you make to Argon by *a ton*.

If you still are finding this limit to be way too small for you, you can contact me on discord (`@dank_meme01`) and request an API token which will let you make a lot more requests. You can also contact me to check how close you are to hitting the quota if you already have a public mod using Argon.

# GET /v1/status

Checks whether the server is up and running.

The response is a JSON object, with keys:

* `active` - boolean, whether the API is active and can be used
* `total_nodes` - integer, amount of nodes currently registered
* `active_nodes` - integer, amount of nodes that can process auth requests
* `ident` - string, server identification

# GET /v1/validation/check

Checks whether an authtoken is valid and matches the given account ID.

**Note: if you also want to validate/retrieve the user's account name without making additional requests to the GD server, you can use the [check_strong](#get-v1validationcheck_strong) endpoint!**

Parameters are expected to be passed as a query string, aka `/v1/validation/check?arg1=x&arg2=y&arg3=z`. The parameters for this endpoint are:

* `account_id` - integer, ID of user's Geometry Dash account
* `authtoken` - string, the authtoken supplied by the user

The response is a JSON object, with keys:

* `valid` - boolean, whether this token is valid and matches the supplied account ID
* `cause` - string, **only present if `valid` is `false`**, describes why exactly the token validation failed

## Notes

Upon a validation failure, it is recommended to make the user regenerate the authtoken.

# POST /v1/validation/check-many

Same as `/v1/validation/check` but allows for checking up to 50 accounts at once. The body must be a JSON object, with the following format:

```json
{
    "users": [
        {
            "id": 12345,
            "token": "abcdefg"
        },
        {
            "id": 54321,
            "token": "gfedcba"
        }
    ]
}
```

The response is a JSON object, with the following format:

```json
{
    "users": [
        {
            "id": 12345,
            "valid": true
        },
        {
            "id": 54321,
            "valid": false,
            "cause": "invalid token"
        }
    ]
}
```

Same rules apply to each object in the response as in `/v1/validation/check` - specifically `cause` is only present if `valid` is `false`.

# GET /v1/validation/check-strong

*(Previously known as `/v1/validation/check_strong`, both remain valid but it is advised to use the one with a dash)*

Checks whether an authtoken is valid and matches the given account ID, user ID and username that are sent by the user.

Parameters are expected to be passed as a query string, aka `/v1/validation/check_strong?arg1=x&arg2=y&arg3=z`. The parameters for this endpoint are:

* `account_id` - integer, ID of user's Geometry Dash account
* `user_id` - integer (optional), user ID of user's Geometry Dash account, recommended to pass this, but if not passed then it won't be checked
* `username` - string (optional), the username of the account, if empty then `valid` will **always** be false
* `authtoken` - string, the authtoken supplied by the user

The response is a JSON object, with keys:

* `valid` - boolean, whether this token is valid and matches all the fields supplied
* `valid_weak` - boolean, whether this token is valid and matches **at least** the supplied account ID. Always `true` if `valid` is `true`
* `cause` - string, **only present if `valid` and `valid_weak` are `false`**, describes why exactly the token validation failed
* `username` - string, **only present is `valid_weak` is `true`**, is the actual username of the user as stored inside the token

## Notes

**Please read this if you will be using this endpoint.**

This endpoint is useful for mods that want to not only authenticate users but also gather their usernames (for example in a multiplayer mod that is basically necessary). Normally you could make a separate request to GD API for this, but this can be bad for multiple reasons:

* When done client-side, this would mean a separate request for every username you need to fetch, leading to easy rate limits for your users
* For fetching and caching usernames server-side, you need your server to not be blocked by boomlings, and you still need to be mindful of rate limits

Fortunately, when the user creates an Argon authtoken, their username (as provided by the GD servers, not the user) is already stored in the token, so it is possible to retrieve it using this endpoint.

### How to use

You can make a request to this endpoint with the user-provided authtoken and credentials, account ID is necessary while user ID and username can be omitted, although it is recommended to pass them. If the response has `valid_weak` set to `true`, then at least the account ID matches and the user isn't spoofing that, and if `valid` is also `true` then the username matches as well. The actual name of the user, as stored in the authtoken is always returned in the response if the token is valid.

## IMPORTANT ⚠️

You should not assume that the returned `username` by this endpoint is up-to-date and 100% correct. Usually it will be, but there are caveats, some of which can cause strong validation to fail, and some can't.

In short, as a mod developer if `valid` returns `false` while `valid_weak` returns `true`, you should make the user refresh their login in GD account settings, as this will likely solve the issue. You can also set `forceStrong` to true when creating the token so that a weak one cannot be created altogether.

* If the user changes their name (properly, with a login refresh), the Argon client should immediately delete the token. But in case that token still gets used later, or the user attempts to spoof the username via a mod, it will create a mismatch and cause `valid` to be `false`, because the authtoken still stores their old username.

* If the user changes their name but does not refresh their login, there is now a mismatch between what their game thinks their name is, and what the GD servers think. If the user does the name change **before** creating an authtoken, then a weak one will be created, and `valid` will return `false` during validation. If the user does the name change **after** they have created an authtoken, then strong validation will succeed fine, but the returned username will **NOT** match their actual new username.

* If the username has inconsistent casing, for example it is DankMeme01 on the GD servers but dankmeme01 in their game (which is totally valid), Argon will still consider them the same and set `valid` to `true`. This is why it's recommended that you use the username returned in the response instead of the one given by the user, even if strong validation succeeds. Additionally make sure to trim and convert your usernames to lowercase if you are going to be comparing them :)

# POST /v1/validation/check-strong-many

Same as `/v1/validation/check-strong` but allows for checking up to 50 accounts at once. The body must be a JSON object, with the following format:

```json
{
    "users": [
        {
            "id": 12345,
            "token": "abcdefg"
        },
        {
            "id": 54321,
            "user_id": 123154135,
            "name": "amongus",
            "token": "gfedcba"
        }
    ]
}
```

Just like `/v1/validation/check-strong`, `user_id` and `name` can be omitted in each object.

The response is a JSON object, with the following format:

```json
{
    "users": [
        {
            "id": 12345,
            "valid": true,
            "valid_weak": true,
            "username": "foo"
        },
        {
            "id": 54321,
            "valid": false,
            "valid_weak": false,
            "cause": "invalid token"
        }
    ]
}
```

# POST /v1/validation/check-data-many

Checks whether the authtoken is valid and matches the supplied account ID, and returns the user data (account ID, user ID and username). Unlike all the other endpoints, this one lets you retrieve the accurate user ID and username that are stored inside of the token.

Up to 50 users can be queried in a single request. The body must be a JSON object, with the following format:

```json
{
    "users": [
        {
            "id": 12345,
            "token": "abcdefg"
        },
        {
            "id": 54321,
            "token": "gfedcba"
        }
    ]
}
```

The response is a JSON object, with the following format:

```json
{
    "users": [
        {
            "id": 12345,
            "valid": true,
            "user_id": 55555,
            "username": "robtop"
        },
        {
            "id": 54321,
            "valid": false,
            "cause": "invalid token"
        }
    ]
}
```

# GET /v1/ws

> **NOTE:** to prevent potential abuse, this API currently can only be used if you have a custom API token. It will not work otherwise! You can feel free to request one if you are making a middle to large sized mod, or otherwise want to use this API, see [Rate limits](#rate-limits) section.

Besides traditional HTTP API, Argon provides a way for servers to establish a persistent WebSocket connection at `/v1/ws`, for improved latency and bandwidth usage.

The WebSocket API can use 3 protocols: plain JSON, zstd-compressed JSON and raw binary. The protocol is chosen by the client in the [Auth](#auth) message.

For a quick start, you can skip to [Examples](#examples) section.

## Message format

In case plain JSON is used, messages must be sent with the `Text` WebSockets frame type. In case of JSON with zstd or raw binary, `Binary` messages should be used. Zstd compression applies to the entire JSON payload being sent.

For JSON or JSON with zstd, the format of the message is as follows:

```json
{
    "type": "insert type here",
    "data": { /* ... */ }
}
```

For binary encoding, the following rules are used:

* All numbers are encoded in **Little-endian**. This means 0x1234 must be serialized as `34 12` and not `12 34`.
* Numeric IDs must be used for the type, they are encoded as a **1-byte unsigned integer**
* Between fields, there's no separators of any kind.
* Fields are encoded in the exact same order as they are shown in the JSON examples
* Names of the fields are not encoded, only values
* Fields that are optional must be prefixed with `0x01` if they are present, otherwise they are encoded as a single byte `0x00` to indicate their absence. **This applies only for Requests, not Responses!**
* Strings are encoded in UTF-8 (though typically they are always ASCII anyway), and **prefixed with a 2-byte unsigned integer indicating the length**. For example, "ABC" is encoded as `03 00 41 42 43`
* Arrays are **prefixed with a 2-byte unsigned integer indicating the length**. For example, `[1, 2, 3, 4]` (assuming integers are 32-bit) is encoded as `04 00 00 00 00 01 00 00 00 02 00 00 00 03 00 00 00 04`
* All integers are encoded as 32-bit signed integers, unless otherwise specified.
* Booleans are encoded in 1 byte, `true` is `01` and `false` is `00`

Important note for binary encoding: some fields in responses are optional and are omitted entirely when encoding responses. Make sure to account for that.

## Messages

### Auth

*Numeric ID: 1*

This message must be sent as the first message. If the client sends a different message or does not send the Auth message after a certain amount of time, the connection will be terminated. This message **must be sent in plain JSON**, no matter what protocol you decide to use later.

```json
{
    "token": "Your API token",
    "proto": "json"
}
```

The `proto` key can be one of: `json`, `json-zstd`, `binary-v1`

After this message is sent, an [AuthAck](#authack) message is sent by the server **in plain JSON**. This confirms the authentication attempt, and all the future messages **MUST** use the selected protocol. If the client specified an invalid protocol or an invalid API token, the [FatalError](#fatalerror) message is sent back using **plain JSON**, and the connection is closed.

### AuthAck

*Numeric ID: 2*

This message contains no data, and is there to simply confirm that the authentication was successful.

### FatalError

*Numeric ID: 3*

This message is sent by the server when it encounters a fatal issue. After this message, the connection is closed and no more data can be sent.

```json
{
    "error": "a custom error message indicating what went wrong"
}
```

### Error

*Numeric ID: 4*

This message is sent by the server when the client sends an invalid request, is rate limited, or a server issue has occurred during processing the request.

```json
{
    "error": "a custom error message indicating what went wrong"
}
```

### Status

*Numeric ID: 5*

This message contains no data (`data` key in the response may be null or an empty object). It is used to request the server's status, same as the [/v1/status](#get-v1status) endpoint.

### StatusResponse

*Numeric ID: 6*

The `data` object in the response is identical to the one in the [/v1/status endpoint](#get-v1status).

### Validate

*Numeric ID: 7*

This message contains a list of up to 50 user tokens to be checked. See the [/v1/validation/check endpoint](#get-v1validationcheck) for additional information. The response is a `ValidateResponse` message. Format of the request:

```json
[
    {
        "id": 12345,
        "token": "abcdefg"
    },
    {
        "id": 54321,
        "token": "gfedcba"
    }
]
```

### ValidateResponse

*Numeric ID: 8*

This is a response to the [Validate](#validate) message. See the [/v1/validation/check endpoint](#get-v1validationcheck) for additional information. Format:

```json
[
    {
        "id": 12345,
        "valid": true
    },
    {
        "id": 54321,
        "valid": false,
        "cause": "invalid token"
    }
]
```

### ValidateStrong

*Numeric ID: 9*

This message contains a list of up to 50 user tokens to be checked. See the [/v1/validation/check-strong endpoint](#get-v1validationcheck-strong) for additional information. The response is a `ValidateStrongResponse` message. Format of the request:

```json
[
    {
        "id": 12345,
        "token": "abcdefg"
    },
    {
        "id": 54321,
        "user_id": 123154135,
        "name": "amongus",
        "token": "gfedcba"
    }
]
```

When using binary format, if `name` and/or `token` aren't present, a single `0x00` byte is encoded in their place. If they are present, they must be prefixed with a `0x01` byte.

### ValidateStrongResponse

*Numeric ID: 10*

This is a response to the [ValidateStrong](#validatestrong) message. See the [/v1/validation/check-strong endpoint](#get-v1validationcheck-strong) for additional information. Format:

```json
[
    {
        "id": 12345,
        "valid": true,
        "valid_weak": true,
        "username": "foo"
    },
    {
        "id": 54321,
        "valid": false,
        "valid_weak": false,
        "cause": "invalid token"
    }
]
```

### ValidateCheckDataMany

*Numeric ID: 13*

This message contains a list of up to 50 user tokens to be checked. See the [/v1/validation/check-data-many endpoint](#post-v1validationcheck-data-many) for additional information. The response is a `ValidateCheckDataManyResponse` message. Format of the request:

```json
[
    {
        "id": 12345,
        "token": "abcdefg"
    },
    {
        "id": 54321,
        "token": "gfedcba"
    }
]
```

### ValidateCheckDataManyResponse

*Numeric ID: 14*

This is a response to the [ValidateCheckDataMany](#validatecheckdatamany) message. See the [/v1/validation/check-data-many endpoint](#post-v1validationcheck-data-many) for additional information. Format:

```json
 [
    {
        "id": 12345,
        "valid": true,
        "user_id": 55555,
        "username": "robtop"
    },
    {
        "id": 54321,
        "valid": false,
        "cause": "invalid token"
    }
]
```

## Examples

### JSON

Here's what a plaintext JSON communication might look like:

Client (authenticating):
```json
{
    "type": "Auth",
    "data": {
        "token": "my-super-secret-api-token-zzzzz",
        "proto": "json"
    }
}
```

Server response:
```json
{
    "type": "AuthAck",
    "data": null
}
```

Client (wanting to validate 1 user token):
```json
{
    "type": "Validate",
    "data": [
        {
            "id": 12345,
            "token": "abcdef.mytoken"
        }
    ]
}
```

Server response:
```json
{
    "type": "ValidateResponse",
    "data": [
        {
            "id": 12345,
            "valid": true
        }
    ]
}
```

### Binary

Before

Client (authenticating):

```json
{
    "type": "Auth",
    "data": {
        "token": "my-super-secret-api-token-zzzzz",
        "proto": "binary-v1"
    }
}
```

Server response:
```json
{
    "type": "AuthAck",
    "data": null
}
```

Note: In the following examples, the binary data is split into separate lines, and comments are added for clarity. In the real-world application, all the data is encoded contigously, with no separation.

Client (wanting to validate 2 user tokens):
```
07                                               # Type: Validate (7)
02 00                                            # Length of the 'data' array
39 30 00 00                                      # 1st account ID: 12345
0e 00 61 62 63 64 65 66 2e 6d 79 74 6f 6b 65 6e  # 1st token: 'abcdef.mytoken'
31 d4 00 00                                      # 2nd account ID: 54321
08 00 74 6f 6b 65 6e 61 62 63                    # 2nd token: 'tokenabc'
```

Server response:
```
08                                            # Type: ValidateResponse (8)
02 00                                         # Length of the 'data' array
39 30 00 00                                   # 1st account ID: 12345
01                                            # 1st token valid: true
31 d4 00 00                                   # 2nd account ID: 54321
00                                            # 2nd token valid: false
0d 00 69 6e 76 61 6c 69 64 20 74 6f 6b 65 6e  # cause: 'invalid token'
```