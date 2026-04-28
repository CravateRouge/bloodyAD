# bloodyAD test lab

This directory contains everything you need to stand up a reproducible
Active Directory lab for running the bloodyAD functional test suite
(`tests/test_functional.py`, `tests/test_authentication.py`).

The lab matches the hard-coded values in the test suite:

| Setting       | Value                 |
| ------------- | --------------------- |
| Domain        | `bloody.corp`         |
| DC hostname   | `main.bloody.corp`    |
| NetBIOS name  | `BLOODY`              |
| Admin user    | `Administrator`       |
| Admin pass    | `Password123!`        |
| CA common name| `bloody-MAIN-CA`      |
| CA template   | `User`                |

## What you need

- One Windows Server 2022 or 2025 VM (fresh install, 2+ vCPU, 4+ GB RAM).
  Any hypervisor works — Hyper-V, Proxmox, VMware, UTM (ARM build of
  Server 2025), VirtualBox.
- Network connectivity from the test machine (where you run `python
  -m unittest`) to the VM on TCP 53/88/389/445/636 and UDP 53/88.
- Python 3.8+ with `impacket` and `certipy-ad` on `PATH` on the test
  machine — see `requirements-dev.txt` in the repo root.

## Quick start

### 1. Provision the DC

Boot the fresh Windows Server VM, log in as local Administrator, and
run the two bootstrap scripts in order:

```powershell
# Copy this directory onto the VM (over SMB, or via clipboard paste into
# PowerShell ISE — the scripts are tiny).

# Stage 1: rename host + promote to DC (reboots automatically).
.\setup-dc-stage1.ps1

# After reboot, log in as BLOODY\Administrator (password: Password123!)
# and run stage 2.
.\setup-dc-stage2.ps1
```

Total time: ~10–15 minutes including reboots.

Both scripts accept parameters if you want different names:

```powershell
.\setup-dc-stage1.ps1 -DomainName "test.lab" -NetbiosName "TEST" -AdminPassword "SomethingElse"
```

If you change these, update `tests/secrets.json` and the CA name in
`tests/test_functional.py` to match — the test file currently hardcodes
`bloody-MAIN-CA` and the `User` template name.

### 2. Configure the test client

On the machine where you run the tests (your mac, a linux box, etc.):

```bash
# 2a. Install dev dependencies.
pip install -r requirements-dev.txt

# 2b. Copy the secrets template and fill in the VM's IP.
cp tests/secrets.json.example tests/secrets.json
$EDITOR tests/secrets.json
#  → set "ip" to the VM's IP (e.g. 10.0.0.10)

# 2c. Make the hostname resolvable. Either set the VM's IP as your DNS
#     server, or add a /etc/hosts entry:
echo "10.0.0.10 main.bloody.corp" | sudo tee -a /etc/hosts
```

### 3. Run the suite

```bash
cd path/to/bloodyAD
python -m unittest tests.test_functional -v
python -m unittest tests.test_authentication -v
```

The functional suite exercises most `add`/`get`/`set`/`remove` primitives
against the lab. It leaves the domain clean on exit (objects it creates
get deleted in `tearDownClass`), so you can re-run it without resetting
the VM. If a run aborts mid-test, snapshot your VM before the run so you
can roll back.

## Tips

- **Snapshot before first run.** The suite creates and deletes users,
  group memberships, GMSAs, DNS records, trust objects, etc. If it ever
  aborts halfway, snapshot rollback is faster than cleaning up by hand.
- **Use a host-only / internal network.** The lab uses a default-weak
  password and no patching. Don't route it to the public internet.
- **Keep the VM on for the whole development cycle.** DC promotion takes
  long enough that you don't want to redo it; just suspend/resume.
- **Unit tests don't need any of this.** If you're only touching pure
  Python (formatters, CLI parsing, tree display), run the AD-free tests:

  ```bash
  python -m unittest tests.test_formatters tests.test_msldap_module tests.unit_test
  ```

## Reproducing on Proxmox

The repo does not ship a Proxmox provisioning pipeline — everyone's
Proxmox cluster is different (storage backend, network VLANs, template
IDs). What has worked for me:

1. Build a Windows Server 2022 template once (sysprep'd, QEMU agent
   installed, RDP enabled).
2. Clone it, attach to your lab VLAN, boot.
3. RDP in, copy this directory onto the VM, run the two PS1 scripts.
4. Point `tests/secrets.json` at the VM's IP.

If you want to automate the clone + IP assignment step for your own
cluster, see `tests/lab/.local/` (gitignored) for user-specific
Terraform / Ansible glue. A starter Terraform manifest for
`Telmate/proxmox` is provided in the `.local.example/` sibling
directory — copy it, adjust for your cluster, and gitignore your copy.

## Reproducing on UTM / Apple Silicon

Apple Silicon can't run GOAD (x86_64-only Windows images). But UTM +
Windows Server 2025 ARM64 eval works:

1. Download the Windows Server 2025 ARM64 ISO from the Microsoft
   Evaluation Center.
2. Create a UTM VM: 4 vCPU, 6 GB RAM, 60 GB disk, attach the ISO.
3. Install Windows, log in as local Admin, run `setup-dc-stage1.ps1`.
4. After reboot, log in as domain Admin, run `setup-dc-stage2.ps1`.
5. Note the VM's IP from `ipconfig`, update `tests/secrets.json`.

## Troubleshooting

### `test_01AuthCreateUser` fails with `Cannot find a certificate template called 'User'`
The User template exists by default but may not be published. In
`certsrv.msc` → `Certificate Templates` → right-click → `New` →
`Certificate Template to Issue` → pick `User`. Or re-run
`setup-dc-stage2.ps1` — it tries to publish it automatically.

### `getTGT.py: command not found`
You're running from a shell that doesn't have the venv activated or
`requirements-dev.txt` isn't installed. Fix:

```bash
source .venv/bin/activate
pip install -r requirements-dev.txt
```

### `socket.gaierror: [Errno 8] nodename nor servname provided`
DNS resolution for `main.bloody.corp` is failing. Either point your
resolver at the DC or add the `/etc/hosts` entry described above.

### `impacket` Kerberos calls time out
The test prefix uses `-t 300`. If you're on a slow link or the VM is
under heavy load, bump it higher in `tests/test_functional.py` line
`bloody_prefix`.
