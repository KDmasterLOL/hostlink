set shell := ['bash', '-eu', '-o', 'pipefail', '-c']

default:
    just --list

# Source-only checks; they are intentionally separate from native acceptance.
fmt:
    cargo fmt --all -- --check

check:
    cargo check --workspace --locked

test:
    cargo test --workspace --locked

clippy:
    cargo clippy --workspace --all-targets --locked -- -D warnings

package-agent target source output:
    python3 scripts/package_hostlink.py agent {{quote(target)}} {{quote(source)}} {{quote(output)}}

package-hub target source output:
    python3 scripts/package_hostlink.py hub {{quote(target)}} {{quote(source)}} {{quote(output)}}

package-controller target source output:
    python3 scripts/package_hostlink.py controller {{quote(target)}} {{quote(source)}} {{quote(output)}}

package-test:
    python3 -m unittest discover -s scripts -p test_package_hostlink.py -v
