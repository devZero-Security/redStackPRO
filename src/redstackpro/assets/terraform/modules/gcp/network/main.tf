# A redStackPRO network is a routing domain. Members reach each other privately.

resource "google_compute_network" "this" {
  name                    = lower(var.name)
  project                 = var.project
  auto_create_subnetworks = false
  routing_mode            = "REGIONAL"
}
