package api.authz

default allow = false

allow {
    has_fields
    no_invalid_fields
}

# Ensure fields exist
has_fields {
    fields := input.request.body.fields
    is_array(fields)
}

# Ensure all fields are whitelisted
no_invalid_fields {
    fields := input.request.body.fields

    invalid := {
        field |
        some i
        field := fields[i]
        not allowed_field(field)
    }

    count(invalid) == 0
}

# Whitelist lookup (configurable via data)
allowed_field(field) {
    some i
    field == data.allowed_fields[i]
}
