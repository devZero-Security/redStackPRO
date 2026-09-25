variable "name" {
  type = string
}

variable "vpc_id" {
  description = "id of the parent network."
  type        = string
}

variable "cidr" {
  type = string
}

variable "availability_zone" {
  description = "Where this subnet lands. Every subnet in the export shares one zone."
  type        = string
}

variable "nat" {
  description = "Route this subnet through the gateway. Decided by the compiler, which can see whether any member lacks a public address; exposure alone cannot answer it. See 0021."
  type        = bool
  default     = false
}

variable "egress" {
  description = "allowed or none. Carried for readability; the nat input is what writes the route."
  type        = string

  validation {
    condition     = contains(["allowed", "none"], var.egress)
    error_message = "egress must be allowed or none."
  }
}

variable "exposure" {
  description = "internet, local, or none. Rendered by the provider; on AWS internet means the subnet routes to the internet gateway."
  type        = string

  validation {
    condition     = contains(["internet", "local", "none"], var.exposure)
    error_message = "exposure must be internet, local, or none."
  }
}

variable "internet_gateway_id" {
  type = string
}

variable "nat_gateway_id" {
  description = "Null when no segment in this network asked for outbound routing."
  type        = string
  default     = null
}
