package api.authz

import future.keywords.in
import future.keywords.if

default allow = false

allow {
    has_fields
    no_invalid_fields
}

# Helper: parse the body from the header
raw_body := input.request.headers["x-original-body"]

parsed_body := json.unmarshal(urlquery.decode(raw_body))

# Ensure fields exist
has_fields {
    fields := parsed_body.fields
    is_array(fields)
}

# Ensure all fields are whitelisted
no_invalid_fields {
    fields := parsed_body.fields

    invalid := {
        field |
        some i
        field := fields[i]
        not allowed_field(field)
    }

    count(invalid) == 0
}

# Whitelist lookup (from data.allowed_fields)
allowed_field(field) {
    some i
    field == data.allowed_fields[i]
}
