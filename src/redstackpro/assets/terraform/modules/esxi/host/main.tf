# Every redStackPRO host kind uses this module. A Linux host deploys from an OVA
# URL the operator supplies; a Windows host clones a prepared template and is
# customized with sysprep. The kind distinction is carried by inputs. See 0015.

variable "name" { type = string }
variable "node_id" { type = string }
variable "kind" { type = string }
variable "resource_pool_id" { type = string }
variable "datastore_id" { type = string }
variable "datacenter_id" { type = string }
variable "network_id" { type = string }
variable "cores" { type = number }
variable "memory" { type = number }
variable "windows" {
  type    = bool
  default = false
}
variable "ip_address" { type = string }
variable "netmask" { type = number }
variable "gateway" { type = string }
variable "ssh_public_key" { type = string }
variable "disk_size" {
  type    = number
  default = 40
}

variable "linux_ova_url" {
  type    = string
  default = ""
}
variable "windows_template" {
  type    = string
  default = ""
}

# -- range inputs, defaulted so an offense range never sets them.
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
  # Azure/vSphere sysprep wants a valid Windows password; fall back only to keep
  # an offense-range plan valid (a range always sets lab_password).
  windows_password = var.lab_password != "" ? var.lab_password : "Chang3MeR3dStackPro!"
  computer_name    = substr(upper(replace(var.name, "/[^a-zA-Z0-9]/", "")), 0, 15)
}

# Linux: deploy from the operator's OVA URL, customized in through OVF/guestinfo.
resource "vsphere_virtual_machine" "linux" {
  count            = var.windows ? 0 : 1
  name             = lower(var.name)
  resource_pool_id = var.resource_pool_id
  datastore_id     = var.datastore_id
  num_cpus         = var.cores
  memory           = var.memory

  network_interface {
    network_id = var.network_id
  }

  ovf_deploy {
    remote_ovf_url    = var.linux_ova_url
    disk_provisioning = "thin"
  }

  # Cloud images read cloud-init from guestinfo. the admin account, the keys, the shared
  # password and the static address are handed in here; the exact keys depend on
  # the OVA and are finalized at live-test.
  vapp {
    properties = {
      "hostname"    = lower(var.name)
      "public-keys" = var.ssh_public_key
      "password"    = var.lab_password
    }
  }
}

# Windows: clone a prepared template and customize with sysprep, setting the
# admin password and a static address. WinRM is stood up by the template's own
# setup (or the range ansible), the same posture as the other on-prem backend.
data "vsphere_virtual_machine" "win_template" {
  count         = var.windows ? 1 : 0
  name          = var.windows_template
  datacenter_id = var.datacenter_id
}

resource "vsphere_virtual_machine" "windows" {
  count            = var.windows ? 1 : 0
  name             = lower(var.name)
  resource_pool_id = var.resource_pool_id
  datastore_id     = var.datastore_id
  num_cpus         = var.cores
  memory           = var.memory
  guest_id         = data.vsphere_virtual_machine.win_template[0].guest_id
  scsi_type        = data.vsphere_virtual_machine.win_template[0].scsi_type

  network_interface {
    network_id   = var.network_id
    adapter_type = data.vsphere_virtual_machine.win_template[0].network_interface_types[0]
  }

  dynamic "disk" {
    for_each = data.vsphere_virtual_machine.win_template[0].disks
    content {
      label            = "disk${disk.key}"
      size             = disk.key == 0 ? var.disk_size : disk.value.size
      unit_number      = disk.key
      thin_provisioned = disk.value.thin_provisioned
    }
  }

  clone {
    template_uuid = data.vsphere_virtual_machine.win_template[0].id

    customize {
      windows_options {
        computer_name  = local.computer_name
        admin_password = local.windows_password
      }

      network_interface {
        ipv4_address = var.ip_address
        ipv4_netmask = var.netmask
      }

      ipv4_gateway = var.gateway
    }
  }
}

output "ip_address" {
  value = var.ip_address
}

output "private_address" {
  value = var.ip_address
}

output "public_address" {
  value = null
}

output "name" {
  value = lower(var.name)
}
