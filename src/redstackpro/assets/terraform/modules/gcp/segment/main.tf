# A redStackPRO segment is a subnet inside exactly one network.
# egress and exposure are provider agnostic in the topology; this module renders
# them into GCP resources. See decision 0007.

resource "google_compute_subnetwork" "this" {
  name                     = lower(var.name)
  project                  = var.project
  region                   = var.region
  network                  = var.network
  ip_cidr_range            = var.cidr
  private_ip_google_access = true
}

# Members with no external address still need outbound for package installation.
#
# Whether any member lacks one is not visible from here: exposure is a ceiling,
# so a segment can permit public addresses and still hold hosts that took none.
# The compiler can see the members, so it decides and passes the answer in.
# See 0021.
resource "google_compute_router" "this" {
  count   = var.nat ? 1 : 0
  name    = "${lower(var.name)}-router"
  project = var.project
  region  = var.region
  network = var.network
}

resource "google_compute_router_nat" "this" {
  count                              = var.nat ? 1 : 0
  name                               = "${lower(var.name)}-nat"
  project                            = var.project
  region                             = var.region
  router                             = google_compute_router.this[0].name
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "LIST_OF_SUBNETWORKS"

  subnetwork {
    name                    = google_compute_subnetwork.this.id
    source_ip_ranges_to_nat = ["ALL_IP_RANGES"]
  }
}
