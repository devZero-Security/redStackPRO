variable "name" {
  type = string
}

variable "project" {
  type = string
}

variable "region" {
  type = string
}

variable "network" {
  description = "self_link of the parent network."
  type        = string
}

variable "cidr" {
  type = string
}

variable "nat" {
  description = "Provision Cloud NAT. Decided by the compiler, which can see whether any member lacks an external address; exposure alone cannot answer it. See 0021."
  type        = bool
  default     = false
}

variable "egress" {
  description = "allowed or none. Carried for readability; the nat input is what provisions the path out."
  type        = string

  validation {
    condition     = contains(["allowed", "none"], var.egress)
    error_message = "egress must be allowed or none."
  }
}

variable "exposure" {
  description = "internet, local, or none. Rendered by the provider; on GCP internet means members may hold an external address."
  type        = string

  validation {
    condition     = contains(["internet", "local", "none"], var.exposure)
    error_message = "exposure must be internet, local, or none."
  }
}
