package the_bridge.authz

default allow = false

# Rule 1: Allow Sarah Lee (VP M&A) to access merger targets
allow {
    input.user == "sarah.lee@bank.com"
    input.action == "read_merger_targets"
    input.resource == "/data/merger_targets"
}

# Rule 2: Allow fund transfers for allowed users
allow {
    input.action == "transfer_funds"
    input.user == "sarah.lee@bank.com"
}

# Rule 3: Allow general read actions on non-restricted resources
allow {
    input.action == "tools/list"
}

allow {
    input.action == "initialize"
}

# Rule 4: Block direct writes to corporate config files (/etc/config)
allow {
    not is_etc_config_write
}

is_etc_config_write {
    input.action == "write"
    contains(input.resource, "/etc/config")
}

is_etc_config_write {
    contains(input.action, "delete")
    contains(input.resource, "/etc/config")
}
