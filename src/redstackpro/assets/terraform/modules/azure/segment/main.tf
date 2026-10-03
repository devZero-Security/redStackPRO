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
  description = "Give this subnet's private hosts outbound through a NAT gateway. The compiler decides it (a host with no public IP in an egress-allowed segment)."
}

resource "azurerm_subnet" "this" {
  name                 = lower(var.name)
  resource_group_name  = var.resource_group
  virtual_network_name = var.vnet_name
  address_prefixes     = [var.cidr]
}

# Egress for hosts with no public IP. A NAT gateway coexists with instances that
# do have a public address (like GCP Cloud NAT, unlike an AWS route table), so an
# internet-exposed subnet still gives its private members (a collector, an
# operator) a route out. Azure is retiring default outbound, so this is the
# explicit path. count-gated on var.nat.
resource "azurerm_public_ip" "nat" {
  count               = var.nat ? 1 : 0
  name                = "${lower(var.name)}-nat-ip"
  resource_group_name = var.resource_group
  location            = var.location
  allocation_method   = "Static"
  sku                 = "Standard"
}

resource "azurerm_nat_gateway" "this" {
  count               = var.nat ? 1 : 0
  name                = "${lower(var.name)}-nat"
  resource_group_name = var.resource_group
  location            = var.location
  sku_name            = "Standard"
}

resource "azurerm_nat_gateway_public_ip_association" "this" {
  count                = var.nat ? 1 : 0
  nat_gateway_id       = azurerm_nat_gateway.this[0].id
  public_ip_address_id = azurerm_public_ip.nat[0].id
}

resource "azurerm_subnet_nat_gateway_association" "this" {
  count          = var.nat ? 1 : 0
  subnet_id      = azurerm_subnet.this.id
  nat_gateway_id = azurerm_nat_gateway.this[0].id
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
