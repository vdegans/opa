package api.authz

default allow = false

# Allow only if all requested fields are whitelisted
allow {
    valid_fields
}

# Ensure every field in the request is allowed
valid_fields {
    requested := input.body.fields

    # Set of fields that are not allowed
    invalid := {
        f |
        f := requested[_]
        not allowed_field(f)
    }

    count(invalid) == 0
}

# Field whitelist (configurable via data)
allowed_field(field) {
    field == fields.allowed_fields[_]
}