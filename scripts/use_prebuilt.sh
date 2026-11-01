#!/usr/bin/env bash
# Source this file from the release root to select its checked client build.
_lk_clients="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/out"
(cd "$_lk_clients" && printf '%s  %s\n' \
  6ebbf94e4e38fd46650789d10fa3811246d5b43f5b72cdc254f294586c089dbb read_only_client \
  279df1f56a44e38eb587bce82a0ed271b01bfa5b12c2d0193a2a3ee84d0690e8 inactive_b_client_ver \
  | sha256sum --check) || { unset _lk_clients; return 1; }
export LK_MUTATION_CLIENT_SHA=279df1f56a44e38eb587bce82a0ed271b01bfa5b12c2d0193a2a3ee84d0690e8
unset _lk_clients
