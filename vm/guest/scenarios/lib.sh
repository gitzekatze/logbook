# Shared by the scenarios (sourced, as root). note ACTION KEY=VALUE... writes
# one line to the harness log /out/harness.jsonl: what the harness did, when
# (wall clock and seconds since boot, which a clock jump doesn't move). The
# harness log is the expected result of a recorded day (build plan V04).
note() {
    action=$1; shift
    fields=""
    for kv in "$@"; do
        fields="$fields,\"${kv%%=*}\":\"${kv#*=}\""
    done
    printf '{"wall":"%s","uptime":%s,"action":"%s"%s}\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)" "$(cut -d' ' -f1 /proc/uptime)" "$action" "$fields" \
        >> /out/harness.jsonl
}
