variable "name" {
  type = string
}

variable "node_id" {
  description = "Topology node id. Becomes the network tag firewall rules key on."
  type        = string
}

variable "kind" {
  description = "redStackPRO node kind. Carried as a label, and drives nothing here."
  type        = string
}

variable "project" {
  type = string
}

variable "zone" {
  type = string
}

variable "subnetwork" {
  description = "self_link of the segment this host attaches to."
  type        = string
}

variable "network_ip" {
  description = "A pinned private address inside the segment's cidr, e.g. a range host locking to GOAD's canonical octets (see 0055). Empty means GCP assigns one from the subnet's DHCP range, the unchanged default."
  type        = string
  default     = ""
}

variable "image" {
  type = string
}

variable "machine_type" {
  type    = string
  default = "e2-medium"
}

variable "disk_size_gb" {
  type    = number
  default = 30
}

variable "disk_type" {
  description = "Boot disk type. pd-balanced (SSD) by default; the GCP default of pd-standard (HDD) throttles IO-heavy provisioning. Override to pd-ssd for max speed or pd-standard to save disk cost."
  type        = string
  default     = "pd-balanced"
}

variable "public_address" {
  description = "Allocate an external address. Decided per host now, bounded by the segment exposure. See 0021."
  type        = bool
  default     = false
}

variable "reserve_ip" {
  description = "Reserve a static external address so the public IP survives a stop/start (redirector C2 domain, jumpbox portal). Only takes effect with public_address. Released on teardown."
  type        = bool
  default     = false
}

variable "admin_username" {
  description = "The Linux admin / SSH account every host authorizes (redop for ops, blueop for a range). One per canvas, set by the compiler."
  type        = string
  default     = "rtadmin"
}

variable "ssh_public_key" {
  description = "Authorized key for the admin account. Supplied at run time, never generated."
  type        = string
}

variable "extra_tags" {
  type    = list(string)
  default = []
}

# -- range (defense) inputs. Defaulted so an offense range never sets them.

variable "windows" {
  description = "Whether this host runs Windows, so the boot script is the PowerShell one."
  type        = bool
  default     = false
}

variable "enable_winrm" {
  description = "A range's Windows host is provisioned over WinRM, so the boot script sets the Administrator password and stands up an HTTPS listener."
  type        = bool
  default     = false
}

variable "lab_password" {
  description = "Shared lab password, set on the admin account and the Windows operator/Administrator. Generated at apply, never in the export."
  type        = string
  default     = ""
}

variable "operator_username" {
  description = "The operator account created on the Windows box and used for the Guacamole login."
  type        = string
  default     = "operator"
}

variable "guac_public_key" {
  description = "The jumpbox Guacamole key, authorized for the admin account on every box so the portal connects with no password on the wire."
  type        = string
  default     = ""
}

variable "guac_private_key" {
  description = "The private half, delivered only to the jumpbox so it drives the Guacamole tiles."
  type        = string
  default     = ""
  sensitive   = true
}

# -- operator workstation (offense Windows operator). Defaulted off so no other
# host runs the setup.

variable "operator_setup" {
  description = "Run the operator workstation setup once at first boot (MobaXterm, browser, tools). The offense Windows operator only; it has no WinRM, so its kit rides the boot script rather than Ansible."
  type        = bool
  default     = false
}

variable "operator_setup_script" {
  description = "The verbatim operator_setup.ps1 contents, delivered as an instance metadata key and fetched by the boot script, so its PowerShell variable syntax needs no template escaping."
  type        = string
  default     = ""
}

variable "operator_hosts" {
  description = "An /etc/hosts block naming the range hosts, exported to the setup script as RSP_HOSTS so MobaXterm sessions and bookmarks resolve by name."
  type        = string
  default     = ""
}

variable "resource_policies" {
  description = "Resource policies to attach, used for the auto stop schedule. Empty leaves the instance on its own, which is the default. See 0057."
  type        = list(string)
  default     = []
}

variable "operator_ssh_key" {
  description = "Private SSH key delivered to the operator box so MobaXterm can key-auth into the stack instead of prompting for the password. The Guacamole key, whose public half is already authorized for the platform account on every host. Empty for every host but the offense Windows operator."
  type        = string
  default     = ""
  sensitive   = true
}
