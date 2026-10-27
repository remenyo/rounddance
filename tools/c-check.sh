#!/bin/bash
# C/C++ decision-determinism check: the rounddance-ffi staticlib must
# report identical decisions to the native host transaction, driven
# from C (gcc) and from C++ (g++, proving C++ linkage compat).
#
# Toolchain policy: latest GCC that ESP-IDF supports — system
# gcc/g++ 14.2.0 with -std=c11/-std=c++17 -Wall -Wextra -Werror -O2.
#
# Usage: tools/c-check.sh
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

echo "== compilers =="
gcc --version | head -1
g++ --version | head -1

echo "== native =="
cargo run -q -p rounddance-hal-host --example host_transaction > /tmp/c-txn-native.txt
head -3 /tmp/c-txn-native.txt

echo "== staticlib =="
cargo build -q -p rounddance-ffi
LIB=target/debug/librounddance_ffi.a
ls -l "$LIB"

echo "== compile C harness =="
gcc -std=c11 -Wall -Wextra -Werror -O2 harness/c/txn.c "$LIB" \
    -o /tmp/c-txn-c -lpthread -ldl -lm
echo "C compile OK"

echo "== compile C++ harness =="
g++ -std=c++17 -Wall -Wextra -Werror -O2 harness/c/txn.cpp "$LIB" \
    -o /tmp/c-txn-cpp -lpthread -ldl -lm
echo "C++ compile OK"

echo "== run C harness =="
/tmp/c-txn-c > /tmp/c-txn-c.txt
tail -2 /tmp/c-txn-c.txt

echo "== run C++ harness =="
/tmp/c-txn-cpp > /tmp/c-txn-cpp.txt
tail -2 /tmp/c-txn-cpp.txt

echo "== decision-match (C + C++ vs fresh native) =="
python3 - <<'EOF'
import re
native = open('/tmp/c-txn-native.txt').read()
c_out = open('/tmp/c-txn-c.txt').read()
cpp_out = open('/tmp/c-txn-cpp.txt').read()

digest_native = re.search(r'DIGEST=(0x[0-9a-f]+)', native).group(1)
trace_native = int(re.search(r'TRACE_LINES=(\d+)', native).group(1))

m = re.search(r'C-DECISION-MATCH: digest (0x[0-9a-f]+), trace_lines=(\d+)', c_out)
assert m, 'C harness verdict line missing'
assert m.group(1) == digest_native, f'C digest {m.group(1)} != native {digest_native}'
assert int(m.group(2)) == trace_native, 'C trace_lines'

m = re.search(r'CPP-DECISION-MATCH: digest (0x[0-9a-f]+), trace_lines=(\d+)', cpp_out)
assert m, 'C++ harness verdict line missing'
assert m.group(1) == digest_native, f'C++ digest {m.group(1)} != native {digest_native}'
assert int(m.group(2)) == trace_native, 'C++ trace_lines'

pinned = open('harness/c/expected.txt').read()
assert digest_native in pinned, 'digest not in expected.txt pin'
print(f'DECISION-MATCH: digest {digest_native}, '
      f'trace_lines={trace_native}, C + C++ == native')
EOF

echo "== test suites =="
cargo test -q -p rounddance-ffi 2>&1 | grep -E "test result" || true
