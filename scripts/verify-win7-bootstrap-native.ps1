# Retired under Huly 1C-1164. Compatible with Windows PowerShell 2.
# The old ZIP/bootstrap-verify harness cannot validate raw binary installation.
# Fail before reading files, credentials, creating roots, or executing a candidate.
throw 'verify-win7-bootstrap-native: RETIRED (1C-1164). No native test executed. See docs/WIN7_REWRITE_ACCEPTANCE.md for the raw binary acceptance gates.'
