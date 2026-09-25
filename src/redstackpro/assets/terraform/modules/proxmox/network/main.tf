# A redStackPRO network is a routing domain. On Proxmox it allocates nothing:
# isolation is by VLAN on the shared bridge, carried by each segment, and
# routing between VLANs is a property of the host network (a precondition, not a
# resource). The module stays for symmetry with the cloud backends and so a
# future SDN backend has a seam to fill. See the registry and 0015.

variable "name" {
  description = "Network name, from the topology node name."
  type        = string
}

output "name" {
  value = var.name
}
