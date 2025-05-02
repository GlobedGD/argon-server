# Server-Side API

This describes the API that should be used by the server of a mod that wants to integrate Argon. For now it includes endpoints for retrieving server status and validating authtokens, but more might come in future for developers.

For a quick example on how to correctly do auth, check the [Argon README](https://github.com/GlobedGD/argon), this document describes some exact details about the API.

Requests to these endpoints don't *have* to have a specific user-agent, although it would be appreciated if you used something unique and something that would make it possible for us to know what mod your requests are for. For example `globed-server/1.0.0` is good, while `python-requests/2.32.0` is not. This way we could know who to contact in case there are issues.

All endpoints here respond with status code 200 and a JSON object, unless critical errors happened or you are rate limited. You should **always** check the status code of the request - if it's not 200 then the data is not a JSON object and could be an error message. A response with code 429 will be returned if you are rate limited - check [Rate Limits](#rate-limits) section for more information.

# Rate limits

To prevent abuse, rate limits apply if you are using our official server (https://argon.globed.dev). If you exceed either of the following limits, you will be temporarily blocked and will receive an HTTP 429 in response:

* 10000 token validations in one day
* 750 validations in one hour

This effectively allows you to authorize ~7 users per minute, which should be enough for most small to medium sized mods (though these limits are subject to change). As described in the [Best Practices](https://github.com/GlobedGD/argon/blob/main/best-practices.md) guide, it is recommended that your server also has its own kind of session tokens, which can often reduce the requests you make to Argon by *a ton*.

If you still are finding this limit to be way too small for you, you can contact me on discord (`@dank_meme01`) and request an API token which will let you make a lot more requests.

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