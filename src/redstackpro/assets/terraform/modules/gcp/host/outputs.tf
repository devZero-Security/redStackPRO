output "private_address" {
  value = google_compute_instance.this.network_interface[0].network_ip
}

output "public_address" {
  value = try(
    google_compute_instance.this.network_interface[0].access_config[0].nat_ip,
    null
  )
}

output "name" {
  value = google_compute_instance.this.name
}
