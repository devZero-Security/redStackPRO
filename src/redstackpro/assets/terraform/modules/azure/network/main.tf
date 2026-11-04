# A redStackPRO network is a routing domain: an Azure virtual network. Members
# reach each other privately; segments are subnets within it.

variable "name" { type = string }
variable "resource_group" { type = string }
variable "location" { type = string }
variable "cidr" { type = string }

variable "create_nat" {
  type        = bool
  default     = false
  description = "Create ONE NAT gateway for this VNet, shared by all its private subnets. Azure caps public IPs per region, so one gateway per VNet (mirrors the AWS network-level NAT) beats one per subnet, which burned a public IP each. The compiler sets it when any segment in the VNet needs egress."
}

resource "azurerm_virtual_network" "this" {
  name                = lower(var.name)
  resource_group_name = var.resource_group
  location            = var.location
  address_space       = [var.cidr]
}

# Egress for private hosts (no public IP), shared across this VNet's subnets. A NAT
# gateway coexists with hosts that do have a public address (like GCP Cloud NAT,
# unlike an AWS route table). Azure is retiring default outbound, so this is the
# explicit path. One public IP for the whole VNet, not one per subnet.
resource "azurerm_public_ip" "nat" {
  count               = var.create_nat ? 1 : 0
  name                = "${lower(var.name)}-nat-ip"
  resource_group_name = var.resource_group
  location            = var.location
  allocation_method   = "Static"
  sku                 = "Standard"
}

resource "azurerm_nat_gateway" "this" {
  count               = var.create_nat ? 1 : 0
  name                = "${lower(var.name)}-nat"
  resource_group_name = var.resource_group
  location            = var.location
  sku_name            = "Standard"
}

resource "azurerm_nat_gateway_public_ip_association" "this" {
  count                = var.create_nat ? 1 : 0
  nat_gateway_id       = azurerm_nat_gateway.this[0].id
  public_ip_address_id = azurerm_public_ip.nat[0].id
}

output "name" {
  value = azurerm_virtual_network.this.name
}

output "id" {
  value = azurerm_virtual_network.this.id
}

output "nat_gateway_id" {
  value = one(azurerm_nat_gateway.this[*].id)
}
