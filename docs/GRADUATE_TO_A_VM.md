# Graduating from your workstation to a small VM

Sharing an app from your work PC is a great way to demo and iterate, and a bad way
to run something people rely on: the machine sleeps, reboots for patches, moves
networks, and sits outside IT's backup and monitoring. This guide moves a running
Perch project to a small always-on host with the **same `perch.yaml` and the same
commands**. Plan on under an hour, most of it waiting on image pulls.

## When to graduate (any one of these)

- A teammate asked "is it down?" because your laptop was asleep.
- The app holds data anyone would miss (that data currently lives on your C: drive).
- You shared the URL beyond your immediate team.
- IT asked what is listening on your workstation. (Sanctioned beats shadow.)

## 1. Provision the host

A basic VPS (1-2 vCPU, 2 GB RAM, ~$5/month: Hetzner, DigitalOcean, Vultr) or a VM
your IT provides on the internal network. Use a current Ubuntu LTS. For a team
app, an IT-provided internal VM is the better citizen: it inherits corporate
backup/monitoring and needs no public exposure.

```bash
ssh user@your-vm
curl -fsSL https://get.docker.com | sh          # Docker Engine, license-free
curl -fsSL https://raw.githubusercontent.com/sknib1337/Perch/main/install.sh | bash
perch doctor
```

## 2. Back up on the workstation

```bash
perch backup                    # dumps every managed postgres to .perch/backups/
```

Then collect what the new host needs:

| Item | Why |
|---|---|
| `perch.yaml` | The whole point: it moves unchanged. |
| `.perch/state.json` | Generated managed-service credentials and share/quarantine state. |
| `.perch/master.key` or `PERCH_MASTER_KEY` | Only if you sealed state (C4); without the key a sealed state file is ciphertext. |
| `.perch/backups/...` | The database dumps from the step above. |
| Your app source (or its git URL) | `build.context` must resolve on the new host; a git URL needs no copying. |

Copy them over (adjust paths):

```bash
scp perch.yaml user@your-vm:~/app/
scp -r .perch user@your-vm:~/app/.perch
```

`.perch/state.json` is `0600` and may be sealed; treat it like the credential file
it is (transfer over SSH only, delete stray copies).

## 3. Bring it up on the VM

```bash
cd ~/app
perch validate
perch up
perch restore db .perch/backups/<project>/db/<latest>.dump    # per postgres service
perch status
```

Because state moved with you, managed services keep their generated credentials;
apps reconnect without edits.

## 4. Point teammates at the new home

- **Internal DNS (best):** ask IT for a name (`app.corp.example.com`) pointing at
  the VM, set it as `route.host`, run `perch up`. The proxy serves it on :80/:443;
  with a resolvable name and reachable :443, Caddy can even do internal-CA TLS or
  a public cert if the host is internet-facing.
- **No DNS yet:** `perch share web` works exactly as it did on the workstation and
  prints the VM's LAN URL. `--tailscale` also works unchanged if the VM joins your
  tailnet.
- For scheduled agents, keep the scheduler alive: run `perch scheduler` under
  systemd (a unit with `ExecStart=perch scheduler`, `Restart=always`).

## 5. Decommission the workstation copy

```bash
perch destroy                   # remove the containers on the workstation
```

Then remove the Windows firewall rules `perch share --fix` created (elevated
PowerShell): `Remove-NetFirewallRule -DisplayName "Perch share <port>"`, and
delete the leftover `.perch/` directory once you have confirmed the VM copy works
(it contains credentials and backups).

## What deliberately does not change

The manifest, the commands, the security posture (identity, egress, mcp, verify
blocks all behave identically), and your workflow: edit `perch.yaml`, `perch up`.
The only thing that changed is that the host no longer goes to lunch when you do.
