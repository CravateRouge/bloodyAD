variable "pm_api_url" {
  type        = string
  description = "Proxmox API URL, e.g. https://proxmox.lan:8006/api2/json"
}

variable "pm_api_token_id" {
  type        = string
  description = "Proxmox API token ID, e.g. terraform@pve!mytoken"
}

variable "pm_api_token_secret" {
  type        = string
  description = "Proxmox API token secret"
  sensitive   = true
}

variable "pm_tls_insecure" {
  type        = bool
  description = "Skip TLS verification on the Proxmox API (set true for self-signed)"
  default     = true
}

variable "target_node" {
  type        = string
  description = "Proxmox node hostname to place the VM on, e.g. pve01"
}

variable "template_name" {
  type        = string
  description = "Name of the Windows Server template to clone (must exist on Proxmox)"
  default     = "win2025-template"
}

variable "vm_name" {
  type        = string
  description = "Name of the DC VM"
  default     = "bloody-dc"
}

variable "cpu_cores" {
  type        = number
  description = "vCPU count for the DC"
  default     = 4
}

variable "memory_mb" {
  type        = number
  description = "Memory (MiB) for the DC"
  default     = 6144
}

variable "bridge" {
  type        = string
  description = "Proxmox bridge to attach the NIC to"
  default     = "vmbr0"
}
