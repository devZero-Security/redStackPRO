variable "name" {
  description = "Network name, from the topology node name."
  type        = string
}

variable "cidr" {
  description = "Address range for the whole routing domain. Segments carve out of it."
  type        = string
}

variable "create_nat" {
  description = "Whether any segment needs outbound routing without a public address."
  type        = bool
  default     = false
}

variable "create_public_subnet" {
  description = "Whether any host took a public address. AWS routes per subnet, so an addressed host cannot share a NAT-routed subnet: it lands in the public subnet instead."
  type        = bool
  default     = false
}

variable "public_subnet_cidr" {
  description = "Range for the public subnet, which holds the NAT gateway and any addressed host. Chosen by the compiler so it cannot overlap a segment."
  type        = string
  default     = null
}

variable "availability_zone" {
  description = "Where the gateway subnet lands. Every subnet in the export shares one zone, so the gateway is never remote to what routes through it."
  type        = string
}
