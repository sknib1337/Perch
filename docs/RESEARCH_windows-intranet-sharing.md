# Research: making Perch usable for intranet webapp sharing from a work Windows PC

*Deep-research report, 2026-07-15. 23 sources fetched, 111 claims extracted, 25
adversarially verified (3 votes each): 22 confirmed, 3 refuted. Confidence labels
reflect source quality after verification.*

**Goal.** A developer builds webapps with AI on a corporate Windows workstation and
wants teammates on the same network to open them in a browser. What must Perch
improve or simplify for that to actually work?

**Headline.** Perch's current happy path quietly assumes three things that are false
on a work Windows PC: that Docker Desktop is available (it is a paid license at most
employers), that teammates can reach the machine (Windows Firewall blocks inbound by
default, in ways that fail silently), and that `*.localhost` route names mean anything
to anyone but the host machine (they never leave it). The fixes are tractable, and
the strongest UX model to copy is Tailscale Serve: one command, one audience scope,
DNS and TLS handled automatically, private by default.

---

## Verified findings

### 1. Docker Desktop is a licensing landmine at work (HIGH confidence)

Docker Desktop requires a paid subscription for commercial use at any organization
with **250+ employees OR $10M+ annual revenue**, and for all government entities.
It is free only for individuals, small businesses under both thresholds, education,
and non-commercial open source. Policy in force since 2021-2022, verified live
against Docker's license page and subscription agreement.

- The restriction covers only the Docker Desktop product. **Docker Engine and Moby
  remain Apache 2.0 and free at any company size**, and Docker Engine installs
  directly inside WSL2 (`systemd=true` in wsl.conf, official apt repo). Microsoft's
  WSL networking docs confirm default localhost forwarding makes Linux-side published
  ports reachable from a Windows browser with no manual setup.
- Caveats: WSL localhost forwarding can intermittently break after sleep/hibernate
  (WSL issues #8696, #12747), and localhost access is machine-local only. LAN
  teammates still need the Windows host IP plus firewall rules.
- Podman is a viable secondary runtime (Apache 2.0, daemonless, rootless), though
  Windows setup (`podman machine init/start`, WSL prerequisite) takes more manual
  steps than Docker Desktop (MEDIUM confidence).

**Implication for Perch.** `perch doctor` currently tells a Windows user to
"Install Docker Desktop". At most employers that advice creates a licensing
violation. Doctor should detect a Docker Engine running inside WSL2 (and Podman)
as first-class, and the docs should lead corporate users down the license-free path.

Sources: [docs.docker.com/subscription/desktop-license](https://docs.docker.com/subscription/desktop-license/),
[Docker Subscription Service Agreement](https://www.docker.com/legal/docker-subscription-service-agreement),
[Docker pricing FAQ](https://www.docker.com/pricing/faq/),
[Microsoft WSL networking](https://learn.microsoft.com/en-us/windows/wsl/networking),
[nickjanetakis.com WSL2 install guide](https://nickjanetakis.com/blog/install-docker-in-wsl-2-without-docker-desktop),
[Podman LICENSE](https://github.com/containers/podman/blob/main/LICENSE)

### 2. Windows Firewall makes LAN sharing fail silently, three ways (HIGH confidence)

All from Microsoft Learn (updated 2025), verified verbatim:

1. **Inbound is blocked by default.** Caddy on 80/443 is unreachable from teammates
   until an explicit inbound allow rule exists.
2. **The non-admin prompt is a trap.** If a non-admin user is shown the first-listen
   firewall prompt, *block* rules are created no matter what they click ("It doesn't
   matter what option is selected"), those rules take precedence, and they must be
   deleted before the prompt can ever reappear.
3. **Corporate GPO/MDM can disable local policy merge.** When merge is disabled,
   locally created rules (e.g. `New-NetFirewallRule` from a setup script) succeed at
   creation time but have **no effect**; only centrally deployed rules can open the
   port. Reachability also depends on the active network profile (Domain/Private/Public).

**Implication for Perch.** A fire-and-forget `New-NetFirewallRule` is not a fix. Perch
needs a diagnose-and-verify flow: create the rule, then actually probe reachability
on a non-loopback address, and when the rule provably doesn't take effect, say
"ask IT to deploy this rule" instead of failing silently.

Source: [Microsoft Learn, Windows Firewall rules](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/rules)

### 3. Naming: `*.localhost` never leaves the machine; mDNS is a fallback, not a fix (HIGH confidence)

- Perch's starter route (`web.localhost`) resolves to loopback on the host only.
  Teammates need a name (or IP) that resolves to the workstation.
- mDNS can advertise names with **no admin rights, no hosts-file edits, no DNS
  server** (per the DDEV maintainer's proposal and RFC 6762), but only under
  `*.local`, with **no wildcard support**, and enterprise networks commonly block
  mDNS across VLANs. Workable fallback (`app-name.local`), not the primary answer.

Sources: [DDEV issue #6663](https://github.com/ddev/ddev/issues/6663), RFC 6762

### 4. Tailscale Serve is the UX benchmark to copy or integrate (HIGH confidence)

`tailscale serve 3000` exposes a local service to teammates at a stable
`machine-name.tailnet.ts.net` hostname with **automatically provisioned, publicly
trusted TLS** (no mkcert, no internal CA, no cert distribution), **private to the
tailnet by default**. Public exposure (`tailscale funnel`) is a separate, explicit,
admin-gated command, disabled by default.

- Qualifications: teammates must install Tailscale and join the tailnet (corporate
  IT may block unapproved VPN clients); Funnel is limited to ports 443/8443/10000;
  there is a one-time HTTPS/MagicDNS enablement step.
- **Refuted in verification (0-3): `.ts.net` Serve names are *not* globally
  resolvable.** Tailnet membership is required. Serve does not bypass onboarding.

**Implication for Perch.** Don't reinvent intranet DNS and cert distribution. Ship a
`perch share` that (a) drives Tailscale when it's present, and regardless (b) copies
the pattern: one command, one audience scope, DNS+TLS handled, secure by default.

Sources: [Tailscale blog, Serve and Funnel](https://tailscale.com/blog/reintroducing-serve-funnel),
[Tailscale Serve docs](https://tailscale.com/docs/features/tailscale-serve),
[Funnel CLI reference](https://tailscale.com/docs/reference/tailscale-cli/funnel)

### 5. CLI simplification: zero-flag defaults and example-led help (MEDIUM confidence)

- Defaults must serve the majority case with zero flags: "most users are not going
  to find the right flag and remember to use it all the time" (clig.dev, corroborated
  by NN/g defaults research and Microsoft telemetry showing ~95% of users keep all
  defaults). Intranet sharing should be one command's default behavior, not a flag
  combination.
- Help should lead with one or two concrete example invocations rather than an
  exhaustive option list.
- (A specific "rewrite error messages" claim failed verification 0-3 and is
  excluded; that only means its cited evidence failed, not that good errors are bad.)

Sources: [clig.dev](https://clig.dev/), NN/g "The Power of Defaults"

### 6. A workstation host is shadow IT; say so honestly (MEDIUM confidence)

Hosting team webapps on a personal workstation is a documented shadow-IT pattern:
such services often run with weak or default credentials, sit outside the org's
security tooling (EDR/NGAV), and their data risks falling outside policy-driven
backup and encryption (hedged as "may" in the sources; corroborated by Verizon 2025
DBIR: 46% of compromised systems with corporate logins were non-managed devices).
Sleep/power settings plus the WSL2 localhost-after-sleep bug compound the
reliability case.

**Implication for Perch.** Frame the workstation as a demo/dev-sharing stopgap.
Document a "graduate to a small sanctioned VM" path (same `perch.yaml`, different
host). Lean on the existing secure-by-default posture so shared apps aren't the
weak-credential cliché.

Sources: [CrowdStrike shadow IT](https://www.crowdstrike.com/en-us/cybersecurity-101/cloud-security/shadow-it/),
[IBM shadow IT](https://www.ibm.com/think/topics/shadow-it),
[Gartner](https://www.gartner.com/smarterwithgartner/dont-let-shadow-it-put-your-business-at-risk)

---

## Prioritized improvements (evidence-backed backlog input)

| # | Improvement | Grounded in | Size |
|---|---|---|---|
| 1 | **Runtime detection beyond Docker Desktop.** `perch doctor` detects Docker Engine in WSL2 and Podman; stops recommending Docker Desktop unconditionally; docs add a licensing note and a license-free corporate install path. | Finding 1 | M |
| 2 | **`perch share`: diagnose-and-verify LAN reachability.** One command that creates the firewall rule, detects the non-admin block-rule trap and GPO merge-disabled case, probes reachability from a non-loopback address, and prints the exact URL teammates should use. Fails loud with "ask IT to deploy this rule" when local rules can't work. | Finding 2 | L |
| 3 | **Teammate-reachable naming by default.** Replace `*.localhost` in the sharing story: print `http://<host-ip>` and/or advertise `app.local` via mDNS as fallback; document why `web.localhost` works only on the host. | Finding 3 | M |
| 4 | **Tailscale Serve integration.** When `tailscale` is on PATH, `perch share` offers to drive `tailscale serve` (stable name + trusted TLS + tailnet-private, no firewall work). Document tailnet onboarding cost honestly. | Finding 4 | M |
| 5 | **Intranet HTTPS story, documented.** Options and trade-offs: plain HTTP on a trusted LAN (and which browser APIs need a secure context), Caddy's internal CA with a root-cert install step on teammate machines, mkcert, or Tailscale certs. Pick one recommended default. | Findings 3, 4 (open question) | M |
| 6 | **Zero-flag happy path + example-led help.** `perch share` (and bare `perch`) print concrete examples first; the common intranet case needs no flags. | Finding 5 | S |
| 7 | **Honest workstation framing + graduation path.** README/GETTING_STARTED section: the work PC is a stopgap (sleep, patching, shadow-IT exposure); a small sanctioned VM with the same `perch.yaml` is the destination. | Finding 6 | S |
| 8 | **YAML 1.1 coercion warnings in `perch validate`.** PyYAML parses YAML 1.1: unquoted `no`/`off`/`on` become booleans, unquoted `3.10` becomes a float (the "Norway problem"). Validate can warn on suspicious coercions in `env` values. | clig.dev/noyaml sources (extracted, angle 4) | S |

## Refuted claims (excluded from the above)

- `.ts.net` Serve names are globally resolvable (0-3). They require tailnet membership.
- Dokploy/Coolify/CapRover native tunnel-support comparison (1-2). Comparative-tools
  evidence beyond Tailscale did not survive verification.
- The specific "error messages measurably reduce time-to-recovery" citation (0-3).

## Caveats and open questions

- **Source quality.** Docker licensing and Windows Firewall findings rest on primary
  vendor/Microsoft documentation (strong). Podman, WSL2 install, CLI design, and
  shadow-IT findings rest on blogs, guideline sites, and vendor education pages
  (verified and corroborated, but weaker).
- **Time-sensitivity.** Docker subscription thresholds/prices have changed before
  (Dec 2024) and should be re-checked before docs ship. Tailscale CLI syntax is
  current mid-2026 but vendor-controlled.
- **License-free is not IT-policy-free.** Corporate policy can block WSL, Hyper-V, or
  Tailscale regardless of licensing. No verified data quantified how common that is.
- **Open questions.**
  1. How do Coolify/Dokploy/CapRover/Dokku actually handle first-run onboarding and
     sharing (that research angle mostly failed verification)?
  2. How prevalent are corporate blocks on WSL2/Hyper-V/VPN clients on managed fleets?
  3. Best pure-intranet HTTPS without Tailscale: Caddy internal CA vs mkcert vs plain
     HTTP, and what breaks under each (HSTS, secure-context APIs)?
  4. Can Perch reliably detect disabled local firewall policy merge (registry /
     `Get-NetFirewallProfile`) at setup time, and what is the exact probe sequence to
     verify real LAN reachability?
