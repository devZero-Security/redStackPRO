# A redStackPRO network is a routing domain. On vSphere it allocates nothing:
# isolation is by VLAN on a port group, carried by each segment, and routing
# between VLANs is a property of the physical network. The module stays for
# symmetry with the other backends. See 0015.

variable "name" {
  type = string
}

output "name" {
  value = var.name
}
