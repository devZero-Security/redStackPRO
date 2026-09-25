# A segment is a VLAN carrying a CIDR. The VLAN id tags each host's NIC on the
# shared bridge; the CIDR is where the backend allocated the static host
# addresses (Proxmox has no cloud DHCP). No resource is created: the VLAN exists
# the moment a NIC is tagged with it on a VLAN-aware bridge. See 0015.

variable "name" {
  type = string
}

variable "cidr" {
  type = string
}

variable "vlan_id" {
  type = number
}

output "vlan_id" {
  value = var.vlan_id
}

output "cidr" {
  value = var.cidr
}
