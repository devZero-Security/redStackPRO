variable "name" {
  type = string
}

variable "node_id" {
  description = "Topology node id. Carried as a tag so an instance can be traced back to the topology."
  type        = string
}

variable "kind" {
  description = "redStackPRO node kind. Carried as a tag, and drives nothing here."
  type        = string
}

variable "vpc_id" {
  description = "id of the network this host's segment belongs to. The security group lives in it."
  type        = string
}

variable "subnet_id" {
  description = "id of the segment this host attaches to."
  type        = string
}

variable "private_ip" {
  description = "A pinned private address inside the segment's cidr, e.g. a range host locking to GOAD's canonical octets (see 0055). Empty means AWS assigns one from the subnet's range, the unchanged default."
  type        = string
  default     = ""
}

variable "image_owner" {
  description = "AMI owner id or alias. An id is per region, so the image is resolved by owner and name."
  type        = string
}

variable "image_name" {
  description = "AMI name pattern, most recent match wins."
  type        = string
}

variable "instance_type" {
  type    = string
  default = "t3.medium"
}

variable "disk_size_gb" {
  type    = number
  default = 30
}

variable "public_address" {
  description = "Allocate a public address. Decided per host now, bounded by the segment exposure. See 0021."
  type        = bool
  default     = false
}

variable "auto_public_ip" {
  description = "Give an address-less host on an internet-exposure (IGW-routed) segment an auto-assigned public IP for egress only, the way redStack does. No Elastic IP, and the security group still locks inbound. Without it such a host has no route out (an IGW is useless to an address-less instance and the segment has no NAT). See 0021."
  type        = bool
  default     = false
}

variable "key_name" {
  description = "Key pair the export created from ssh_public_key. Never generated here."
  type        = string
}

variable "admin_username" {
  description = "The Linux admin / SSH account every host authorizes (redop for ops, blueop for a range). One per canvas, set by the compiler; cloud-init creates it."
  type        = string
  default     = "rtadmin"
}

variable "ssh_public_key" {
  description = "Authorized key for the admin account, written into a Linux host by cloud-init. Supplied at run time, never generated. The key pair puts it on the image default user; this creates the admin account the Ansible layer connects as, mirroring the GCP module."
  type        = string
}

variable "windows" {
  description = "Stand up a WinRM listener, because a Windows host is not reached over ssh. See 0019."
  type        = bool
  default     = false
}

variable "enable_winrm" {
  description = "Provision this Windows host over WinRM. A range's controllers and members are (the boot script sets the Administrator password and stands up an HTTPS listener); an offense range's Windows operator self-provisions and is left alone. See goad-native-recreation."
  type        = bool
  default     = false
}

variable "elastic_ip" {
  description = "Give this host a stable Elastic IP. True for the jumpbox and the redirector, the two hosts reached from outside, so their address survives a stop and start; every other host keeps the auto-assigned public address it uses only for outbound."
  type        = bool
  default     = false
}

variable "lab_password" {
  description = "Shared lab password, set on the admin account here and on the Windows operator account. Generated at apply, never in the export."
  type        = string
  default     = ""
  sensitive   = true
}

variable "operator_username" {
  description = "Operator account name, used on the Windows box for RDP and the Guacamole login."
  type        = string
  default     = "operator"
}

variable "guac_public_key" {
  description = "The jumpbox's Guacamole key, authorized for the admin account on every box so the portal connects without a password."
  type        = string
  default     = ""
}

variable "guac_private_key" {
  description = "The private half of the Guacamole key, written only on the jumpbox so the portal can use it. Empty on every other host."
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

variable "operator_setup_script_b64" {
  description = "The operator_setup.ps1 contents, base64-encoded so it embeds in user_data without escaping (the script itself uses PowerShell here-strings). The boot script decodes and runs it once."
  type        = string
  default     = ""
}

variable "operator_hosts" {
  description = "An /etc/hosts block naming the range hosts, exported to the setup script as RSP_HOSTS so MobaXterm sessions and bookmarks resolve by name."
  type        = string
  default     = ""
}

variable "operator_ssh_key" {
  description = "Private SSH key delivered to the operator box so MobaXterm can key-auth into the stack instead of prompting for the password. The Guacamole key, whose public half is already authorized for the platform account on every host. Empty for every host but the offense Windows operator."
  type        = string
  default     = ""
  sensitive   = true
}
