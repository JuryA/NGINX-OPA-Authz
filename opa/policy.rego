# This server version only supports POST requests, essentially.
# Our web server fulfills exactly this function, meaning it sends the request data to OPA
# to check whether it passes or not, via a POST request.

package server_rules

import input.http_method as http_method    # The HTTP method that our rule needs to analyze.
                        # Rego does not have built-in functions for handling HTTP requests (which makes sense),
                        # as these are theoretically expected to come from an external server.

default allow = false  # Prevents access if no matching rule is found (default deny).

# This is the basic case.
allow {
    input.uses_jwt == "false"
    check_permission
}

check_permission {
    all := data.roles[input.role][_]
    all == input.operation
}

# -------------------JWT Rules------------------------

# This is the case where a JWT is present.
allow {
    input.uses_jwt == "true"
    allow_jwt
    # token_is_valid
}

# "allow" is the base rule of our policy.
allow_jwt {
    check_permission_jwt
    check_time_valid
}

# Checks whether the user's roles are consistent with the operation they want to perform.
check_permission_jwt {
    data.roles[payload["wlcg.groups"][_]][_]
            == input.operation
}

check_time_valid {
    payload.exp >= time.now_ns()
} else {  # Case where the token never expires.
    payload.iat == payload.exp
    payload.exp == payload.nbf
}

# "Function" to validate and extract information from the Bearer token.
payload := p {
    v := input.token
    startswith(v, "Bearer ")  # Ensures it is indeed a Bearer token.
    t := substring(v, count("Bearer "), -1)  # Extracts the token.
    [_, p, _] := io.jwt.decode(t)
}
