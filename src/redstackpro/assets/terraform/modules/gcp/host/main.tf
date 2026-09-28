# Every redStackPRO host kind uses this module. The kind distinction is carried by
# inputs (image, public_address, machine_type) rather than by separate modules,
# because per kind host modules would be near identical copies.

locals {
  tags = concat([var.node_id, "redstackpro", var.kind], var.extra_tags)
  # The region a regional external address lives in, derived from the zone
  # (us-east4-a -> us-east4).
  region = join("-", slice(split("-", var.zone), 0, 2))
}

# A reserved (static) external address, so a stop/start keeps the same public IP.
# Only hosts whose address must survive a restart take one -- the redirector (its
# C2 callback domain must keep resolving) and the jumpbox (its Guacamole/SSH entry
# point). A reserved address is released on teardown like any other resource, so a
# fresh deploy still gets a new IP; it only holds steady across stop/start of the
# same range.
resource "google_compute_address" "this" {
  count   = var.public_address && var.reserve_ip ? 1 : 0
  name    = "${lower(var.name)}-ip"
  project = var.project
  region  = local.region
}

resource "google_compute_instance" "this" {
  name         = lower(var.name)
  project      = var.project
  zone         = var.zone
  machine_type = var.machine_type
  tags         = local.tags

  labels = {
    redstackpro_kind    = var.kind
    redstackpro_node_id = replace(var.node_id, "_", "-")
  }

  # The auto stop schedule, when the canvas asked for one. GCP applies the
  # policy itself, so nothing of ours has to be running or hold a credential
  # for the range to turn off.
  resource_policies = var.resource_policies

  boot_disk {
    initialize_params {
      image = var.image
      size  = var.disk_size_gb
      # SSD-backed by default. The unset default is pd-standard (HDD, ~0.75
      # IOPS/GB), which throttles every IO-heavy provisioning step -- docker
      # image extraction, apt unpacking, the Kali dist-upgrade, OpenSearch --
      # and is the main reason a GCP build runs far slower than the same tree on
      # AWS (gp3 SSD). pd-balanced closes almost all of that gap at ~half the
      # cost of pd-ssd.
      type = var.disk_type
    }
  }

  network_interface {
    subnetwork = var.subnetwork
    # Pinned when the topology locks this host to a specific address (a range on
    # GOAD's canonical octets); null lets GCP assign one from the
    # subnet's DHCP range, the unchanged default.
    network_ip = var.network_ip != "" ? var.network_ip : null

    dynamic "access_config" {
      for_each = var.public_address ? [1] : []
      # A reserved address when this host asked for a stable IP, otherwise an
      # ephemeral one (nat_ip null lets GCP assign it).
      content {
        nat_ip = var.reserve_ip ? google_compute_address.this[0].address : null
      }
    }
  }

  # Each box self-provisions at boot, the low-touch path, the same as the AWS
  # backend's user_data. A Windows host runs the PowerShell setup (operator
  # account, RDP, and for a range the Administrator password plus an HTTPS WinRM
  # listener); a Linux host takes ssh-keys to create the admin account, and for a range a
  # startup script that sets the shared password, authorizes the Guacamole key,
  # and drops the jumpbox credential files.
  metadata = merge(
    {
      block-project-ssh-keys = "TRUE"
    },
    var.windows ? {
      windows-startup-script-ps1 = templatefile("${path.module}/windows-startup.ps1.tftpl", {
        operator_username = var.operator_username
        lab_password      = var.lab_password
        enable_winrm      = var.enable_winrm
        operator_setup    = var.operator_setup
        operator_hosts    = var.operator_hosts
        operator_ssh_key  = var.operator_ssh_key
      })
      } : {
      # The guest agent manages the admin account's authorized_keys from this
      # metadata, so the Guacamole key is authorized here rather than fought over
      # in a script.
      ssh-keys = var.guac_public_key != "" ? "${var.admin_username}:${var.ssh_public_key}\n${var.admin_username}:${var.guac_public_key}" : "${var.admin_username}:${var.ssh_public_key}"
    },
    (!var.windows && var.lab_password != "") ? {
      # replace() strips any CRLF so the shebang is not "env: bash\r": the
      # template file can be checked out with Windows line endings, which would
      # otherwise make the guest agent fail the script with exit 127.
      startup-script = replace(templatefile("${path.module}/linux-startup.sh.tftpl", {
        admin_username    = var.admin_username
        lab_password      = var.lab_password
        operator_username = var.operator_username
        guac_public_key   = var.guac_public_key
        guac_private_key  = var.guac_private_key
      }), "\r\n", "\n")
    } : {},
    # The operator workstation setup, delivered verbatim as its own metadata key.
    # The boot script fetches it from the metadata server and runs it once, so
    # the script stays static and its PowerShell syntax needs no escaping.
    var.operator_setup ? {
      operator-setup-ps1 = var.operator_setup_script
    } : {},
  )

  lifecycle {
    ignore_changes = [metadata["ssh-keys"]]
  }
}
