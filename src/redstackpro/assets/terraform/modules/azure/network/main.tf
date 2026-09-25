# A redStackPRO network is a routing domain: an Azure virtual network. Members
# reach each other privately; segments are subnets within it.

variable "name" { type = string }
variable "resource_group" { type = string }
variable "location" { type = string }
variable "cidr" { type = string }

resource "azurerm_virtual_network" "this" {
  name                = lower(var.name)
  resource_group_name = var.resource_group
  location            = var.location
  address_space       = [var.cidr]
}

output "name" {
  value = azurerm_virtual_network.this.name
}

output "id" {
  value = azurerm_virtual_network.this.id
}
