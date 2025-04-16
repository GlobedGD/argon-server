# Server-Side API

This describes the API that should be used by the server of a mod that wants to integrate Argon. It includes authtoken validation, fetching minimal user data like user ID and username from account ID, and anonymous telemetry.

Requests to these endpoints don't *have* to have a specific user-agent, although it would be appreciated if you used something unique and something that would make it possible for us to know what mod your requests are for. For example `globed-server/1.0.0` is good, while `python-requests/2.32.0` is not. This way we could know who to contact in case there are issues.

Some endpoints (namely telemetry) require authentication. To access those, you need a special developer token. If you are a mod developer and you want to access this data, reach out to me on Discord (`@dank_meme01`).

# GET /v1/status

Checks whether the server is up and running.

The response is a JSON object, with keys:

* `active` - boolean, whether the API is active and can be used
* `total_nodes` - integer, amount of nodes currently registered
* `active_nodes` - integer, amount of nodes that can process auth requests
* `ident` - string, server identification

# GET /v1/validation/check

Checks whether an authtoken is valid and matches the given account ID.

Parameters are expeceted to be passed as a query string, aka `/v1/validation/check?arg1=x&arg2=y&arg3=z`. The parameters for this endpoint are:

* `account_id` - integer, ID of user's Geometry Dash account
* `authtoken` - string, the authtoken supplied by the user

If the status code is 200 (OK), the response is a JSON object, with keys:

* `valid` - boolean
