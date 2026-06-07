SCOPE_POLICY = {
    "allowed_dirs": ["./sandbox"],
    "deny_absolute_paths": True,
    "deny_path_traversal": True,
    "allowed_hosts": ["example.com", "httpbin.org"],
    "deny_unlisted_hosts": True,
}

METADATA_POLICY = {
    "deny_markup_in_descriptions": True,
    "deny_unknown_tool_ids": False,
    "description_max_length": 500,
    "disallowed_patterns": ["<script", "javascript:", "eval(", "exec("],
}

def check_metadata(tool_description: str) -> tuple[bool, str]:
    for pattern in METADATA_POLICY["disallowed_patterns"]:
        if pattern in tool_description:
            return False, f"METADATA_VIOLATION: disallowed pattern '{pattern}' in description"
    if len(tool_description) > METADATA_POLICY["description_max_length"]:
        return False, f"METADATA_VIOLATION: description too long ({len(tool_description)} > {METADATA_POLICY['description_max_length']})"
    return True, "ok"

def check_scope_path(path: str) -> tuple[bool, str]:
    if path.startswith("/") or ".." in path:
        return False, f"SCOPE_VIOLATION: absolute or traversal path '{path}'"
    return True, "ok"

def check_scope_host(host: str) -> tuple[bool, str]:
    if host not in SCOPE_POLICY["allowed_hosts"]:
        return False, f"SCOPE_VIOLATION: host '{host}' not in allowlist"
    return True, "ok"
