# A segment is a VLAN on a standard-vSwitch port group. The VM NICs attach to it
# by its network id, resolved after the port group exists.

variable "name" { type = string }
variable "host_system_id" { type = string }
variable "datacenter_id" { type = string }
variable "vswitch" { type = string }
variable "vlan_id" { type = number }

resource "vsphere_host_port_group" "this" {
  name                = lower(var.name)
  host_system_id      = var.host_system_id
  virtual_switch_name = var.vswitch
  vlan_id             = var.vlan_id
}

# The port group's managed network object, once it exists, for the VM NICs.
data "vsphere_network" "this" {
  name          = vsphere_host_port_group.this.name
  datacenter_id = var.datacenter_id
  depends_on    = [vsphere_host_port_group.this]
}

output "network_id" {
  value = data.vsphere_network.this.id
}
