package api.fields.authz

import future.keywords.in

# Default deny
default allow = false
default denied_fields = {}

###########################
# Helper: parse header safely
###########################
raw_body := input.request.headers["x-original-body"]

parsed_body := json.unmarshal(urlquery.decode(raw_body)) {
    raw_body != ""
} else = {}

###########################
# Normalize and clean requested fields
###########################
# Strip whitespace and convert to lowercase
clean_field(f) = t {
    t := lower(trim(f, " \t\r\n"))
}

requested_fields := { clean_field(f) | f := parsed_body.fields[_] }

# Normalize allowed fields
allowed_fields_set := { clean_field(f) | f := data.allowed_fields[_] }

###########################
# Prefix matching logic
###########################
# A requested field is allowed if:
# - exact match
# - OR it is a subfield of an allowed field (prefix + ".")
is_allowed_field(r) {
    a := allowed_fields_set[_]
    r == a
} {
    a := allowed_fields_set[_]
    startswith(r, concat(".", [a, ""]))
    # equivalent to startswith(r, a + ".")
}

###########################
# Denied fields = those that do NOT match prefix logic
###########################
denied_fields := { r |
    r := requested_fields[_]
    not is_allowed_field(r)
}

###########################
# Allow only if no denied fields exist
###########################
allow {
    count(denied_fields) == 0
}

###########################
# Extract BSN from parsed body
###########################
bsn := parsed_body.burgerservicenummer[0] {
    parsed_body.burgerservicenummer
    count(parsed_body.burgerservicenummer) > 0
}

###########################
# Headers to return to APISIX
###########################
headers := h {
    bsn
    logs := json.marshal(parsed_body)

    h := {
        "bsn": sprintf("%v", [bsn]),
        "logs": logs
    }
}
