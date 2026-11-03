# Retired ZIP bootstrap harness; compatible with Windows PowerShell 2.
# The old ZIP/bootstrap-verify harness cannot validate raw binary installation.
# Fail before reading files, credentials, creating roots, or executing a candidate.
throw 'verify-win7-bootstrap-native: RETIRED. No native test executed. See docs/WIN7_REWRITE_ACCEPTANCE.md for the raw binary acceptance gates.'
