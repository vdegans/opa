package api.authz

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

# Normalize allowed fields as well
allowed_fields_set := { clean_field(f) | f := data.allowed_fields[_] }

# Denied fields = requested - allowed
denied_fields := requested_fields - allowed_fields_set

# Allow only if no denied fields exist
allow {
    count(denied_fields) == 0
}
