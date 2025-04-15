# Client-Side API

TODO: links

This describes the API used by the client side of Argon. You should not need this if you are a mod developer looking to integrate Argon. Instead you might be looking for [the C++ api](https://example.com) and [the server-side api](./server-api.md  )

The base URL for our instance is https://argon.dankmeme.dev

All requests must to this API must have a user agent that starts with a string in format `argon/v1.0.0` where `1.0.0` is the version of Argon used to make the request. Otherwise an error will be returned.

# POST /v1/challenge/start

Starts a verification challenge.

Payload is a JSON object, with keys:

* `accountId` - integer, ID of the Geometry Dash account
* `userId` - integer, user ID of the Geometry Dash account
* `username` - string, username of the Geometry Dash account
* `reqMod` - string, ID of the mod that requested the authtoken, optional
* `preferred` - string, preferred authentication method. See the [Authentication methods](#authentication-methods) section for more information.

The response is of the general response format, [see below](#response-format). The data object has the following properties:

* `method` - string, the chosen authentication method by the server. See the [Authentication methods](#authentication-methods) section for more information.
* `id` - integer, value depends on the authentication method
* `challenge` - integer, is a random challenge value

# POST /v1/challenge/restart

Restarts a verification challenge. If no challenge has been started yet, acts the same as `/v1/challenge/start`.

The payload and the response formats are the same as in the [challenge start endpoint](#post-v1challengestart).

# POST /v1/challenge/verify

Submit the solution to the verification challenge and request the Argon server to verify it.

Payload is a JSON object, with keys:

* `accountId` - integer, account ID of the user
* `solution` - string, solution to the authentication challenge

The response is of the general response format, [see below](#response-format). The data object has the following properties:

* `verified` - boolean, represents whether the challenge has been now successfully verified
* `authtoken` - string, if `verified` is `true`, then this is the generated authtoken for the user
* `pollAfter` - integer, if `verified` is `false`, then this is the duration (in milliseconds) that the client should wait before polling the server again

# GET /v1/challenge/verifypoll

Check whether account verification is done.

The response is identical to that of [/v1/challenge/verify](#post-v1challengeverify).

# Response Format

The status code of the response should always be 200 if successful, and 4xx / 5xx on failure (although that is not enforced)

All response objects look like this:

```json
{
    "success": true,
    "error": null,
    "data": {}
}
```

If `success` is `true`:

* `error` must be set to `null`.
* `data` can be either `null` or an object containing endpoint-specific data. Each endpoint documents what should be contained in it.

If `success` is `false`:

* `error` must be set to a string with an error message.

If `success` is missing, or is set to a non-boolean value, or any of the constraints above are violated, the server should be considered incompatible and the current authentication attempt (if any) should be aborted.

# Autentication methods

Possible authentication methods are currently `message` and `comment`. `message` is always chosen as the preferred one, and `comment` is used as a fallback.

## Message authentication

Message authentication works in the following way:

* Argon server sends an account ID of a bot to the user, together with the challenge value
* User completes the challenge, sends a message on Geometry Dash to the bot account with the solution, and then a request to the Argon server to verify the completion
* The server will verify whether the solution is right, and will then wait until it receives a message on Geometry Dash from the user

## Comment authentication

TODO

# Limits

Most, if not all of those limits can be configured, if you are hosting your own Argon instance. The limits on authtoken generation are:

* Up to 5 different accounts in 1 hour from the same IP (only successful attempts count)
* Up to 10 authtoken generation attempts in 1 hour from the same IP (only successful attempts count)
* Up to 25 authtoken generation failures in 1 hour from the same IP

Violating these limits may lead to a temporary or permanent block. Additionally, spamming messages to the bot on GD may get you blocked as well.
