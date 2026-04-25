# Starter Terraform for provisioning a bloodyAD test DC on Proxmox VE.
#
# This clones a pre-built Windows Server 2022/2025 template on your Proxmox
# cluster, boots it, and prints the VM IP. Then you RDP into the VM and run
# tests/lab/setup-dc-stage1.ps1 + stage2.ps1 to bring AD DS + AD CS up.
#
# Copy this directory to tests/lab/.local/ (which is gitignored), fill in
# terraform.tfvars, and run:
#
#   terraform init
#   terraform apply
#
# Prereqs on your Proxmox cluster:
#   - A Windows Server 2022 or 2025 template (sysprep'd, QEMU agent installed).
#   - An API token with VM.Allocate, VM.Clone, VM.Config.*, VM.PowerMgmt.
#   - A bridge (e.g. vmbr0) routing to whatever network you want the lab on.
#
# Provider docs: https://registry.terraform.io/providers/Telmate/proxmox/latest

terraform {
  required_version = ">= 1.3"

  required_providers {
    proxmox = {
      source  = "Telmate/proxmox"
      version = "~> 3.0"
    }
  }
}

provider "proxmox" {
  pm_api_url          = var.pm_api_url
  pm_api_token_id     = var.pm_api_token_id
  pm_api_token_secret = var.pm_api_token_secret
  pm_tls_insecure     = var.pm_tls_insecure
}

resource "proxmox_vm_qemu" "bloody_dc" {
  name        = var.vm_name
  target_node = var.target_node
  clone       = var.template_name
  full_clone  = true

  cores   = var.cpu_cores
  sockets = 1
  memory  = var.memory_mb

  scsihw  = "virtio-scsi-single"
  bios    = "ovmf" # UEFI — Windows Server 2025 defaults to UEFI
  machine = "q35"

  agent = 1 # QEMU guest agent (must be installed in the template)

  network {
    model  = "virtio"
    bridge = var.bridge
  }

  # Don't rebuild the VM just because Proxmox re-ordered disks.
  lifecycle {
    ignore_changes = [
      network,
      disk,
    ]
  }
}

output "vm_ip" {
  description = "IP of the DC as reported by qemu-guest-agent. Use this in tests/secrets.json and /etc/hosts."
  value       = try(proxmox_vm_qemu.bloody_dc.default_ipv4_address, "unknown — wait for guest agent or check Proxmox UI")
}

output "next_steps" {
  value = <<-EOT

    VM "${var.vm_name}" created on node "${var.target_node}".

    1. RDP to the VM (log in as local Administrator).
    2. Copy tests/lab/setup-dc-stage1.ps1 + stage2.ps1 onto the VM.
    3. Run stage1 → wait for reboot → log in as BLOODY\Administrator → run stage2.
    4. Back on your client, update tests/secrets.json with the VM's IP.
    5. Add /etc/hosts entry:  <IP>  main.bloody.corp
    6. Run: python -m unittest tests.test_functional -v
  EOT
}
