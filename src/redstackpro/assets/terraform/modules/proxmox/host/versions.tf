# The bpg/proxmox provider is not in the hashicorp namespace, so a module that
# uses its resources must name the source explicitly; otherwise Terraform looks
# for hashicorp/proxmox and init fails. The root passes the configured provider
# down. See 0002.

terraform {
  required_providers {
    proxmox = {
      source  = "bpg/proxmox"
      version = "~> 0.66"
    }
  }
}
