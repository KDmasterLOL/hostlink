# HostLink source development

Start with the [workspace README](../README.md) for Agent, Controller and Hub
roles and development commands. This branch is for source integration testing;
no release, deployed fleet or production cutover is implied.

For the integrated binary-only source, run from the repository root:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts/tests -v
bash -n scripts/build-win7-candidate.sh
shellcheck scripts/build-win7-candidate.sh
git diff --check
```

Tests use disposable source trees and synthetic binaries/credentials. They do
not read the real HOME PAT or establish runtime installation/native acceptance.
Agent, Controller and packaging compile and pass the Linux workspace tests.
No real Release or native Windows acceptance has been performed. Avoid
concurrent full builds in shared `target`.

For one-raw-binary packaging and four-target release staging follow
[artifact packaging](ARTIFACTS_AND_INVITES.md). Neither script publishes.
See the [documentation index](index.md) for installation and acceptance gates.
