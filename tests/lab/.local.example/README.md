# Proxmox lab provisioning (example — copy to `.local/`)

This directory is a starter Terraform manifest for provisioning a
Windows Server VM on Proxmox VE to host the bloodyAD test lab. It's
**an example**, not a one-click pipeline — every Proxmox cluster is
different and you'll need to point it at your own template, node, and
network.

## What you get

A single VM cloned from an existing Windows Server 2022/2025 template
on your cluster, with enough CPU/RAM to run a DC with AD CS. Nothing
more — no DC promotion, no AD CS install, no domain config. Those steps
live in `../setup-dc-stage1.ps1` and `../setup-dc-stage2.ps1` and are
run inside the guest after Terraform brings it up.

## Prereqs

On your Proxmox cluster:

1. **A Windows Server template.** Install Windows Server 2022 or 2025
   once, install the QEMU guest agent, set it to start on boot, install
   Windows Updates, run sysprep with `/generalize /oobe /shutdown`, and
   convert the VM to a template. If you skip sysprep, the clone will
   work but every VM will share the same SID — fine for throwaway labs.
2. **An API token.** In the Proxmox UI → `Datacenter` → `Permissions` →
   `API Tokens` → Add. Give the user role `PVEVMAdmin` at `/`. Save the
   token ID and secret.
3. A bridge (usually `vmbr0`) that routes to whatever network you want
   the lab on.

On your local machine:

- Terraform 1.3+
- Network access to your Proxmox API URL

## Quick start

```bash
# From the repo root:
cp -r tests/lab/.local.example tests/lab/.local
cd tests/lab/.local
cp terraform.tfvars.example terraform.tfvars
$EDITOR terraform.tfvars   # fill in your Proxmox URL, token, node name

terraform init
terraform apply
# Approve. Wait ~30–60 seconds for clone + boot.

# Terraform prints the VM IP once the guest agent reports it.
```

Then:

1. RDP to the VM's IP as local Administrator.
2. Copy `../setup-dc-stage1.ps1` and `../setup-dc-stage2.ps1` into the VM
   (drag-and-drop into the RDP window works, or SMB from your host).
3. Run stage 1, wait for reboot, log in as `BLOODY\Administrator`, run stage 2.
4. Back on your client, update `tests/secrets.json` with the VM IP and
   add a `/etc/hosts` entry for `main.bloody.corp`.

## Teardown

```bash
terraform destroy
```

VM gone. No leftover state on the Proxmox side (full clone, so the
template is untouched).

## Gotchas

- **`tls_insecure = true` is on by default.** Fine for a home lab with
  a self-signed Proxmox cert. Set to `false` if you have a real cert.
- **QEMU guest agent is required** for Terraform to report the VM's IP.
  If you built the template without it, install it inside the clone and
  restart the guest agent service.
- **UEFI / BIOS mismatch.** `main.tf` sets `bios = "ovmf"` and
  `machine = "q35"`. Windows Server 2025 templates are usually UEFI.
  If your template is legacy BIOS, drop those lines.
- **Provider version.** Telmate/proxmox 3.x has breaking changes from
  2.x. If you have an older Terraform state elsewhere, pin carefully.
