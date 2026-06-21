# Contributing

Thanks for helping out. A few ground rules to keep this small and trustworthy:

- **Keep the core backend-agnostic.** Logic that assumes Docker belongs in
  `docker_backend.py`. The reconciler should never import a concrete backend.
- **Secure-by-default stays default.** Don't loosen container hardening defaults;
  add opt-in knobs instead.
- **No secrets in the manifest.** Only `${ENV_VAR}` references.
- **Tests run without Docker.** Use the fake backend in `tests/` so CI stays fast.

## Dev setup

    pip install -e ".[dev]"
    pytest -q

## Adding a backend

Implement the `Backend` protocol in `perch/backend.py` (e.g. a Compose,
Nomad, or remote-PaaS backend) and wire it into the CLI. The reconciler works
unchanged.

## Signing your work (Developer Certificate of Origin)

To keep the project's copyright provenance clean, contributions are accepted under
the Developer Certificate of Origin (DCO): a lightweight way to certify you wrote
the patch or otherwise have the right to submit it under the project's license. No
paperwork — just a sign-off line on each commit.

Add it automatically with `-s`:

    git commit -s -m "your message"

which appends:

    Signed-off-by: Your Name <you@example.com>

By signing off you agree to the DCO (version 1.1):

    Developer Certificate of Origin
    Version 1.1

    By making a contribution to this project, I certify that:

    (a) The contribution was created in whole or in part by me and I have
        the right to submit it under the open source license indicated in
        the file; or
    (b) The contribution is based upon previous work that, to the best of
        my knowledge, is covered under an appropriate open source license
        and I have the right under that license to submit that work with
        modifications, whether created in whole or in part by me, under the
        same open source license (unless I am permitted to submit under a
        different license), as indicated in the file; or
    (c) The contribution was provided directly to me by some other person
        who certified (a), (b) or (c) and I have not modified it.
    (d) I understand and agree that this project and the contribution are
        public and that a record of the contribution (including all personal
        information I submit with it, including my sign-off) is maintained
        indefinitely and may be redistributed consistent with this project
        or the open source license(s) involved.

Only contribute code you have the right to contribute. Don't paste code of unknown
provenance (from other repositories, Q&A sites, or AI-generated snippets) unless
its license is compatible with Apache-2.0 and you attribute it appropriately.

## Licensing of contributions

Perch is licensed under Apache-2.0. By submitting a contribution (a pull request,
patch, or any change), you agree that your contribution is provided under the
same Apache-2.0 license that covers the project (inbound = outbound), and you
certify the Developer Certificate of Origin below.

### Sign your commits (DCO)

We use the Developer Certificate of Origin -- a lightweight way for you to certify
that you wrote the change, or otherwise have the right to submit it under the
project's license. Add a sign-off to each commit:

    git commit -s

This appends a line to the commit message:

    Signed-off-by: Your Name <you@example.com>

By signing off, you certify the following (Developer Certificate of Origin,
Version 1.1, https://developercertificate.org):

    Developer Certificate of Origin
    Version 1.1

    Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

    Everyone is permitted to copy and distribute verbatim copies of this
    license document, but changing it is not allowed.


    Developer's Certificate of Origin 1.1

    By making a contribution to this project, I certify that:

    (a) The contribution was created in whole or in part by me and I
        have the right to submit it under the open source license
        indicated in the file; or

    (b) The contribution is based upon previous work that, to the best
        of my knowledge, is covered under an appropriate open source
        license and I have the right under that license to submit that
        work with modifications, whether created in whole or in part
        by me, under the same open source license (unless I am
        permitted to submit under a different license), as indicated
        in the file; or

    (c) The contribution was provided directly to me by some other
        person who certified (a), (b) or (c) and I have not modified
        it.

    (d) I understand and agree that this project and the contribution
        are public and that a record of the contribution (including all
        personal information I submit with it, including my sign-off) is
        maintained indefinitely and may be redistributed consistent with
        this project or the open source license(s) involved.
