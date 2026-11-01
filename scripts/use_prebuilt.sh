#!/usr/bin/env bash
# Source this file from the release root to select its checked client build.
_lk_clients="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/out"
(cd "$_lk_clients" && printf '%s  %s\n' \
  8fae48fa460dcc3954af47d5dbd472f0a97b3ecf76a03233004d2bff58287343 read_only_client \
  1d245f18deae520d688031f678a06a2f135d2c3005190d66173e93b2c9387904 inactive_b_client_ver \
  | sha256sum --check) || { unset _lk_clients; return 1; }
export LK_MUTATION_CLIENT_SHA=1d245f18deae520d688031f678a06a2f135d2c3005190d66173e93b2c9387904
unset _lk_clients
