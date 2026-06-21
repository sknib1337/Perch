# Security Policy

## Reporting a vulnerability

Please report security issues privately so they can be fixed before public
disclosure. Do not open a public issue for a vulnerability.

* Use GitHub private vulnerability reporting on this repository (the
  **Security** tab -> **Report a vulnerability**). Reports are delivered
  privately to the maintainers. If the option is not visible, the maintainer
  can enable it under **Settings -> Code security -> Private vulnerability
  reporting**.

Include steps to reproduce and the affected version. We aim to acknowledge
reports within a few days and will keep you posted on the fix and disclosure
timeline.

## Supported versions

Perch is pre-1.0. Security fixes are applied to the latest release -- run the
most recent version.

## Hardening note

Perch runs workloads as hardened containers and binds the console API to
localhost, unauthenticated, by default. Do not expose the console API to a
network without putting authentication in front of it. See the security section
of the README.
