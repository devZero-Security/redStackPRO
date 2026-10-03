# A VNet peering, both directions. Azure requires a peering resource on each side,
# each created in its own VNet and naming the other's id; one alone leaves the link
# half open. Routes exchange automatically once both exist. NSGs do not cross the
# peering, which the generated firewall.tf handles with CIDR based rules. See 0030.

variable "name" {
  type        = string
  description = "Base name for the two peering resources."
}

variable "resource_group" { type = string }

variable "vnet_a_name" {
  type        = string
  description = "Name of the first VNet; the side-A peering is created in it."
}

variable "vnet_a_id" {
  type        = string
  description = "Resource id of the first VNet."
}

variable "vnet_b_name" {
  type        = string
  description = "Name of the second VNet."
}

variable "vnet_b_id" {
  type        = string
  description = "Resource id of the second VNet."
}

resource "azurerm_virtual_network_peering" "a_to_b" {
  name                         = "${var.name}-a-b"
  resource_group_name          = var.resource_group
  virtual_network_name         = var.vnet_a_name
  remote_virtual_network_id    = var.vnet_b_id
  allow_virtual_network_access = true
  allow_forwarded_traffic      = true
}

resource "azurerm_virtual_network_peering" "b_to_a" {
  name                         = "${var.name}-b-a"
  resource_group_name          = var.resource_group
  virtual_network_name         = var.vnet_b_name
  remote_virtual_network_id    = var.vnet_a_id
  allow_virtual_network_access = true
  allow_forwarded_traffic      = true
}
