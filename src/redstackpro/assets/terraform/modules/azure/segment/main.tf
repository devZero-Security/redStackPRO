# A segment is a subnet with a Network Security Group. The NSG is where the
# generated firewall rules land (firewall.tf references it by name), and it is
# associated to the subnet so the rules apply to every NIC in it.

variable "name" { type = string }
variable "resource_group" { type = string }
variable "location" { type = string }
variable "vnet_name" { type = string }
variable "cidr" { type = string }

variable "nat" {
  type        = bool
  default     = false
  description = "Route this subnet's private hosts out through the VNet's shared NAT gateway. The compiler decides it (a host with no public IP in an egress-allowed segment)."
}

variable "nat_gateway_id" {
  type        = string
  default     = ""
  description = "Id of the VNet's shared NAT gateway (output by the network module). Used only when nat = true."
}

resource "azurerm_subnet" "this" {
  name                 = lower(var.name)
  resource_group_name  = var.resource_group
  virtual_network_name = var.vnet_name
  address_prefixes     = [var.cidr]
}

# Associate this subnet to the VNet's shared NAT gateway for egress. The gateway
# (and its one public IP) lives in the network module so a VNet uses a single IP
# rather than one per subnet; see modules/azure/network. count-gated on var.nat.
resource "azurerm_subnet_nat_gateway_association" "this" {
  count          = var.nat ? 1 : 0
  subnet_id      = azurerm_subnet.this.id
  nat_gateway_id = var.nat_gateway_id
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
