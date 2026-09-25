# Every redStackPRO host kind uses this module. A Linux host comes up from a
# cloud image with cloud-init; a Windows host boots an operator-supplied ISO and
# installs unattended, then is provisioned over WinRM. The kind distinction is
# carried by inputs (image, windows, machine sizing), not by separate modules.
# See 0015.

variable "name" { type = string }

variable "node_id" {
  description = "Topology node id. Becomes the VM tag firewall rules key on."
  type        = string
}

variable "kind" {
  description = "redStackPRO node kind. Carried as a tag."
  type        = string
}

variable "proxmox_node" { type = string }
variable "datastore" { type = string }
variable "iso_datastore" { type = string }
variable "bridge" { type = string }
variable "vlan_id" { type = number }

variable "ip_address" {
  description = "Static CIDR address for this host, allocated from its segment."
  type        = string
}

variable "gateway" { type = string }
variable "cores" { type = number }
variable "memory" { type = number }
variable "disk_size" {
  type    = number
  default = 40
}

variable "windows" {
  type    = bool
  default = false
}

variable "ssh_public_key" { type = string }
variable "admin_username" {
  type    = string
  default = "rtadmin"
}

variable "image_url" {
  description = "Cloud image URL for a Linux host. Empty for Windows."
  type        = string
  default     = ""
}

variable "windows_iso_url" {
  description = "Windows installation ISO URL. Empty for Linux."
  type        = string
  default     = ""
}

# -- range (defense) inputs, defaulted so an offense range never sets them.
variable "enable_winrm" {
  type    = bool
  default = false
}
variable "lab_password" {
  type    = string
  default = ""
}
variable "operator_username" {
  type    = string
  default = "operator"
}
variable "guac_public_key" {
  type    = string
  default = ""
}
variable "guac_private_key" {
  type    = string
  default = ""
}

locals {
  # Address without the prefix, for outputs and the Guacamole url.
  ip_only = split("/", var.ip_address)[0]
  # the admin account's authorized keys: the operator key, plus the Guacamole key when set.
  ssh_keys = var.guac_public_key != "" ? [var.ssh_public_key, var.guac_public_key] : [var.ssh_public_key]
}

# The Linux cloud image, downloaded to the ISO datastore at apply and imported as
# the boot disk. Windows has no cloud image, so a Windows host downloads its ISO.
resource "proxmox_download_file" "linux" {
  count        = var.windows ? 0 : 1
  content_type = "import"
  datastore_id = var.iso_datastore
  node_name    = var.proxmox_node
  url          = var.image_url
}

resource "proxmox_download_file" "windows" {
  count        = var.windows ? 1 : 0
  content_type = "iso"
  datastore_id = var.iso_datastore
  node_name    = var.proxmox_node
  url          = var.windows_iso_url
}

resource "proxmox_virtual_environment_vm" "this" {
  name      = lower(var.name)
  node_name = var.proxmox_node
  tags      = ["redstackpro", var.kind]

  agent {
    enabled = true
  }

  cpu {
    cores = var.cores
    type  = "x86-64-v2-AES"
  }

  memory {
    dedicated = var.memory
  }

  network_device {
    bridge  = var.bridge
    vlan_id = var.vlan_id
    model   = "virtio"
  }

  operating_system {
    type = var.windows ? "win11" : "l26"
  }

  # The Proxmox firewall is enabled on the NIC so the per-host rules apply.
  # firewall.tf carries the rules; without this the VM ignores them.
  # (Enabled at the VM firewall options; rules attach by vm_id.)

  # Linux: import the cloud image as the boot disk over virtio-scsi.
  dynamic "disk" {
    for_each = var.windows ? [] : [1]
    content {
      datastore_id = var.datastore
      import_from  = proxmox_download_file.linux[0].id
      interface    = "scsi0"
      size         = var.disk_size
      iothread     = true
    }
  }

  # Windows: a blank SATA disk (no virtio driver needed to see it at install)
  # plus the installation ISO. Unattended install expects an answer file baked
  # into the ISO or delivered on a second volume; that ISO is operator-supplied.
  dynamic "disk" {
    for_each = var.windows ? [1] : []
    content {
      datastore_id = var.datastore
      interface    = "sata0"
      size         = var.disk_size
    }
  }

  dynamic "cdrom" {
    for_each = var.windows ? [1] : []
    content {
      file_id   = proxmox_download_file.windows[0].id
      interface = "ide2"
    }
  }

  # Linux cloud-init: the admin account with the authorized keys and, on a range, the
  # shared password; a static address from the segment.
  dynamic "initialization" {
    for_each = var.windows ? [] : [1]
    content {
      datastore_id = var.datastore

      ip_config {
        ipv4 {
          address = var.ip_address
          gateway = var.gateway
        }
      }

      user_account {
        username = var.admin_username
        password = var.lab_password != "" ? var.lab_password : null
        keys     = local.ssh_keys
      }
    }
  }
}

output "vm_id" {
  value = proxmox_virtual_environment_vm.this.vm_id
}

output "ip_address" {
  value = local.ip_only
}

# The shared outputs.tf (tools/tf_inventory.py) reads these on every backend.
# Proxmox has no allocated public address, so it is null; the static segment
# address is the private one.
output "private_address" {
  value = local.ip_only
}

output "public_address" {
  value = null
}

output "name" {
  value = proxmox_virtual_environment_vm.this.name
}
