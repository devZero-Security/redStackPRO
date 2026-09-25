# A segment is a subnet with a Network Security Group. The NSG is where the
# generated firewall rules land (firewall.tf references it by name), and it is
# associated to the subnet so the rules apply to every NIC in it.

variable "name" { type = string }
variable "resource_group" { type = string }
variable "location" { type = string }
variable "vnet_name" { type = string }
variable "cidr" { type = string }

resource "azurerm_subnet" "this" {
  name                 = lower(var.name)
  resource_group_name  = var.resource_group
  virtual_network_name = var.vnet_name
  address_prefixes     = [var.cidr]
}

resource "azurerm_network_security_group" "this" {
  name                = lower(var.name)
  resource_group_name = var.resource_group
  location            = var.location
}

resource "azurerm_subnet_network_security_group_association" "this" {
  subnet_id                 = azurerm_subnet.this.id
  network_security_group_id = azurerm_network_security_group.this.id
}

output "subnet_id" {
  value = azurerm_subnet.this.id
}

output "nsg_name" {
  value = azurerm_network_security_group.this.name
}
