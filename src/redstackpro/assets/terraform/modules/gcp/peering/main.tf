# A network peering, both directions. GCP requires a peering resource on each
# side naming the other; one alone leaves the connection half open. Routes are
# exchanged automatically once both exist, so there is nothing to add to a route
# table. Firewall is still per network and does not cross the peering, which the
# generated firewall.tf handles with CIDR based rules. See 0030.

variable "name" {
  type        = string
  description = "Base name for the two peering resources."
}

variable "network_a" {
  type        = string
  description = "Self link of the first network."
}

variable "network_b" {
  type        = string
  description = "Self link of the second network."
}

resource "google_compute_network_peering" "a_to_b" {
  name         = "${var.name}-a-b"
  network      = var.network_a
  peer_network = var.network_b
}

resource "google_compute_network_peering" "b_to_a" {
  name         = "${var.name}-b-a"
  network      = var.network_b
  peer_network = var.network_a
}
