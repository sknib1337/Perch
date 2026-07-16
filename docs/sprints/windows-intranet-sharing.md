# Epic: Share from a work Windows PC

A developer on a corporate Windows workstation hosts AI-built webapps with Perch and
teammates on the same network open them in a browser. Grounded in
[docs/RESEARCH_windows-intranet-sharing.md](../RESEARCH_windows-intranet-sharing.md).

Decisions locked for this epic:
- **Runtime**: license-free first. Docker Engine inside WSL2 is the recommended
  corporate path; Docker Desktop is documented as a licensing risk, never assumed.
- **Transport default (deliberate, revisit-able)**: `perch share` v1 serves HTTP on
  the LAN and says so honestly in its output. HTTPS options ship as a later story
  once the intranet-cert open question is researched. Do not silently default.
- **Design rule**: never fire-and-forget. Every environment mutation (firewall rule,
  portproxy) is verified by an actual probe, and failure states name who can fix
  them ("ask IT to deploy this rule").

---

## Sprint 1

**Sprint Goal:** A teammate on the same LAN can open a Perch-hosted webapp by
visiting a URL that one Perch command printed and verified.

### US1: Doctor recognizes license-free runtimes

**As a** developer on a corporate Windows PC, **I want** `perch doctor` to detect a
license-free container runtime (Docker Engine in WSL2, Podman) **so that** I can run
Perch at work without a Docker Desktop subscription my employer doesn't have.

INVEST: Independent (pure detection + messaging). Negotiable (which runtimes rank
first). Valuable (unblocks corporate install). Estimable. Small enough. Testable
with fakes offline + a WSL job note.

Acceptance criteria:
- Given a machine where `docker info` succeeds via any engine (Desktop, WSL2
  docker-ce, Podman's docker-compatible socket), When `perch doctor` runs, Then the
  Docker check passes and names the detected runtime.
- Given a Windows machine with no runtime at all, When `perch doctor` runs, Then the
  fix text offers the license-free WSL2 Docker Engine path first and mentions Docker
  Desktop with its 250-employee/$10M licensing caveat, instead of recommending
  Desktop unconditionally.
- Given WSL is present but no engine is installed inside it, When `perch doctor`
  runs, Then the output includes the two-line WSL2 install pointer (docs link), not
  a generic failure.
- Given the offline test suite, When it runs on both crypto backends, Then new
  detection logic is covered by fakes and the suite passes with no Docker present.

Size: **M**

### US2: `perch share` prints and verifies a teammate-reachable URL

**As a** developer hosting a webapp with Perch, **I want** one command that tells me
the exact URL my teammates can open, verified by a real reachability probe, **so
that** sharing doesn't end with "works on my machine" and a `.localhost` link that
only works for me.

INVEST: Independent of US3 (it reports honestly even when the firewall blocks; US3
automates the fix). Valuable on its own (the demo moment). Estimable. Small enough
once firewall automation is split out. Testable via loopback vs non-loopback probes.

Acceptance criteria:
- Given a routed service running, When I run `perch share <service>`, Then it prints
  `http://<LAN-IP>[:port]` (the host's non-loopback address), never a `*.localhost`
  name, and labels the transport honestly ("HTTP on your LAN").
- Given the printed URL, When `perch share` probes it from the host's own
  non-loopback address, Then it reports REACHABLE or BLOCKED as an explicit result
  line, and BLOCKED names the likely cause (Windows Firewall inbound default) and
  points at US3's fix path.
- Given containers running inside WSL2 NAT (not mirrored mode), When `perch share`
  probes, Then a Windows-LAN-blocked result distinguishes "WSL port not forwarded to
  the Windows host" from "firewall blocked", because the fixes differ.
- Given no service or a service with no port, When I run `perch share <service>`,
  Then it exits non-zero with a one-line message naming what's missing.
- Given the sprint demo (manual), When a second device on the same LAN opens the
  printed URL, Then the app loads.

Size: **L** (the WSL-NAT distinction is why; if it slips, cut the NAT diagnosis to
a stub message and keep the probe)

### US3: Firewall rule with verify, and honest failure on managed machines

**As a** developer whose workstation blocks inbound traffic by default, **I want**
Perch to create the firewall rule for my app's port and then prove it took effect,
**so that** I'm not debugging silent blocks, and when IT policy overrides local
rules I'm told to ask IT instead of being lied to by a "rule created" message.

INVEST: depends on US2's probe (sequenced within the sprint, acceptable). Valuable
(removes the #1 silent failure). Estimable against the researched failure modes.
Testable on a windows-latest CI runner for rule + self-probe; GPO case unit-tested.

Acceptance criteria:
- Given `perch share` reports BLOCKED and the user confirms (or passes `--fix`),
  When Perch creates a scoped inbound allow rule (the app's port, Private/Domain
  profiles only, never Public), Then it re-probes and only reports success if the
  probe now passes.
- Given local firewall policy merge is disabled by GPO (unit-tested via injected
  profile state), When rule creation "succeeds" but the re-probe still fails, Then
  Perch says the rule cannot take effect on this managed machine and prints the
  exact rule spec to hand to IT.
- Given a non-admin shell, When `perch share --fix` runs, Then it detects missing
  elevation up front and prints the elevated one-liner to run, rather than
  triggering the Windows prompt trap that silently creates block rules.
- Given CI on a windows-latest runner, When the integration job runs, Then rule
  creation + self-probe + cleanup pass end-to-end.

Size: **M**

### US4: Windows quick-start docs that match reality

**As a** developer reading the README at work, **I want** a Windows path that
reflects licensing and reachability truthfully, **so that** my first hour isn't
spent discovering Docker Desktop needs a license and `web.localhost` doesn't work
for teammates.

INVEST: all green; pure docs, testable by walkthrough.

Acceptance criteria:
- Given the README/GETTING_STARTED, When a Windows corporate user follows them, Then
  they hit: license-free WSL2 engine install, `perch doctor`, `perch up`,
  `perch share`, in that order, with the Docker Desktop licensing caveat visible
  before any Desktop install suggestion.
- Given the docs, When read end to end, Then the workstation is framed as a
  demo/dev-sharing stopgap with a short "graduate to a small VM, same perch.yaml"
  note (full guide stays in the backlog).
- Given every command in the new sections, When executed against the shipped CLI,
  Then each exists and behaves as documented.

Size: **S**

---

## Sprint 2 (closed): backlog items 1-3, in order

**Sprint Goal:** an app shared from the workstation gets a name and HTTPS story
appropriate to how much it matters, without reinventing DNS or cert distribution.

- **Item 1 shipped: `perch share --tailscale`.** Drives `tailscale serve --bg
  <share-port>`; prints the stable `https://<machine>.<tailnet>.ts.net` URL from
  `tailscale status --json`; honest notes (tailnet-only, first-cert delay). When a
  plain LAN share is BLOCKED and tailscale is on PATH, the output nudges toward it.
- **Item 2 shipped: intranet HTTPS story + `--https`.** Decision recorded (docs
  4b): plain HTTP for quick demos; **Tailscale Serve the moment an app matters**
  (only option with a stable name and an already-trusted cert); Caddy internal CA
  (`--https`, `tls internal` share blocks) when Tailscale is not allowed, with the
  root-cert trust steps documented per OS. Mutually exclusive with --tailscale by
  validation.
- **Item 3 shipped: `perch share --mdns`.** Stdlib-only mDNS responder
  (perch/mdns.py: pure RFC 6762 packet encode/parse, fail-closed on anything
  malformed; thin foreground socket loop). Announces `<service>.local`; documented
  as a fallback because corporate networks commonly block mDNS across VLANs.

## Backlog (groomed order, not in sprint)

| Item | Why not now | Size |
|---|---|---|
| Zero-flag help polish (bare `perch` and subcommands lead with examples) | Real, but doesn't serve this sprint's goal | S |
| `perch validate` YAML 1.1 coercion warnings (Norway problem) | Nice hardening, unrelated to sharing | S |
| Full "graduate to a VM" guide | Stub lands in US4; full guide after share exists | S |
| Real-Docker composed `apply()` e2e (from usability Sprint 1) | Needs a Docker host; unrelated to this epic | M |

## Solo retro (closed 2026-07-16, PR #5 squash-merged as e6273ed)

- **What actually shipped versus the Sprint Goal?** All four stories: US1 doctor
  runtime detection (license-free-first guidance), US2 `perch share` with the
  verified probe and WSL-NAT vs firewall distinction, US3 `--fix` with elevation
  check / Domain-Private scoping / re-probe / GPO handoff-to-IT, US4 docs. Suite
  went 153 to 160 on both crypto backends; a new windows CI job ran the real
  firewall rule round-trip (create, verify via Get-NetFirewallRule, remove) on an
  elevated runner. The Sprint Goal's final inch (a second physical device opening
  the URL) remains the designed-in manual demo step; everything automatable was
  automated and CI-verified.
- **What slowed me down or got re-worked, and why?** Discovering that services are
  never published to host ports (only the Caddy proxy is) forced the share design
  through port-based Caddy site blocks plus extra proxy publishes, rather than a
  simple `-p` on the service container. Cheap to absorb because it surfaced during
  grounding reads, before code was written.
- **One change to try next sprint.** Do the backend-topology read (who publishes
  which ports, which nets) BEFORE grooming stories that touch networking, not
  after; the US2 sizing would have been L-with-reason from the start.
