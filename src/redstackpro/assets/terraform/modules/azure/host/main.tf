# Every redStackPRO host kind uses this module. A Linux host boots from a
# Marketplace image with cloud-init; a Windows host sets the operator password
# natively and, on a range, runs a CustomScript extension that enables the
# built-in Administrator and an HTTPS WinRM listener. The kind distinction is
# carried by inputs, not separate modules. See 0015.

variable "name" { type = string }
variable "node_id" { type = string }
variable "kind" { type = string }
variable "resource_group" { type = string }
variable "location" { type = string }
variable "subnet_id" { type = string }
variable "private_ip" { type = string }

variable "public_address" {
  type    = bool
  default = false
}

variable "size" { type = string }
variable "windows" {
  type    = bool
  default = false
}

variable "image_publisher" { type = string }
variable "image_offer" { type = string }
variable "image_sku" { type = string }
variable "image_version" { type = string }

variable "disk_size" {
  type    = number
  default = 40
}

variable "ssh_public_key" { type = string }
variable "admin_username" {
  type    = string
  default = "rtadmin"
}
variable "operator_username" {
  type    = string
  default = "operator"
}

# -- range inputs, defaulted so an offense range never sets them.
variable "enable_winrm" {
  type    = bool
  default = false
}
variable "lab_password" {
  type    = string
  default = ""
}
variable "guac_public_key" {
  type    = string
  default = ""
}
variable "guac_private_key" {
  type    = string
  default = ""
}

# -- operator workstation (offense Windows operator). Defaulted off, so no other
# host runs the setup. It has no WinRM, so its kit rides a CustomScript extension.
variable "operator_setup" {
  type    = bool
  default = false
}
variable "operator_setup_script_b64" {
  type    = string
  default = ""
}
variable "operator_hosts" {
  type    = string
  default = ""
}

variable "operator_ssh_key" {
  description = "Private SSH key delivered to the operator box so MobaXterm can key-auth into the stack instead of prompting for the password. The Guacamole key, whose public half is already authorized for the platform account on every host."
  type        = string
  default     = ""
  sensitive   = true
}

locals {
  # Azure requires a Windows admin password; fall back to a strong constant only
  # to keep an offense-range plan valid (a range always sets lab_password).
  windows_password = var.lab_password != "" ? var.lab_password : "Chang3MeR3dStackPro!"
}

resource "azurerm_public_ip" "this" {
  count               = var.public_address ? 1 : 0
  name                = lower(var.name)
  resource_group_name = var.resource_group
  location            = var.location
  allocation_method   = "Static"
  sku                 = "Standard"
}

resource "azurerm_network_interface" "this" {
  name                = lower(var.name)
  resource_group_name = var.resource_group
  location            = var.location

  ip_configuration {
    name                          = "primary"
    subnet_id                     = var.subnet_id
    private_ip_address_allocation = "Static"
    private_ip_address            = var.private_ip
    public_ip_address_id          = var.public_address ? azurerm_public_ip.this[0].id : null
  }
}

resource "azurerm_linux_virtual_machine" "this" {
  count                 = var.windows ? 0 : 1
  name                  = lower(var.name)
  resource_group_name   = var.resource_group
  location              = var.location
  size                  = var.size
  admin_username        = var.admin_username
  network_interface_ids = [azurerm_network_interface.this.id]

  admin_ssh_key {
    username   = var.admin_username
    public_key = var.ssh_public_key
  }

  # replace() strips CRLF so a Windows-checked-out template does not feed
  # cloud-init a file with carriage returns.
  custom_data = base64encode(replace(templatefile("${path.module}/cloud-init.yaml.tftpl", {
    admin_username    = var.admin_username
    lab_password      = var.lab_password
    operator_username = var.operator_username
    guac_public_key   = var.guac_public_key
    guac_private_key  = var.guac_private_key
  }), "\r\n", "\n"))

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "StandardSSD_LRS"
    disk_size_gb         = var.disk_size
  }

  source_image_reference {
    publisher = var.image_publisher
    offer     = var.image_offer
    sku       = var.image_sku
    version   = var.image_version
  }
}

resource "azurerm_windows_virtual_machine" "this" {
  count                 = var.windows ? 1 : 0
  name                  = lower(var.name)
  computer_name         = upper(replace(var.name, "/[^a-zA-Z0-9]/", ""))
  resource_group_name   = var.resource_group
  location              = var.location
  size                  = var.size
  admin_username        = var.operator_username
  admin_password        = local.windows_password
  network_interface_ids = [azurerm_network_interface.this.id]

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "StandardSSD_LRS"
    disk_size_gb         = var.disk_size
  }

  source_image_reference {
    publisher = var.image_publisher
    offer     = var.image_offer
    sku       = var.image_sku
    version   = var.image_version
  }
}

# The Windows self-provision: enable the built-in Administrator with the shared
# password and stand up an HTTPS WinRM listener, so Ansible connects as
# Administrator (which becomes the domain Administrator after promotion). The
# operator account and its password are set natively above; this adds only what
# Azure cannot express declaratively. Delivered as a base64 script the command
# decodes and runs, so no external file host is involved.
resource "azurerm_virtual_machine_extension" "winrm" {
  count                = (var.windows && var.enable_winrm) ? 1 : 0
  name                 = "redstackpro-winrm"
  virtual_machine_id   = azurerm_windows_virtual_machine.this[0].id
  publisher            = "Microsoft.Compute"
  type                 = "CustomScriptExtension"
  type_handler_version = "1.10"

  settings = jsonencode({
    commandToExecute = "powershell -ExecutionPolicy Bypass -Command \"[IO.File]::WriteAllText('C:\\\\redstackpro-setup.ps1',[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${base64encode(templatefile("${path.module}/windows-setup.ps1.tftpl", { lab_password = local.windows_password }))}'))); powershell -ExecutionPolicy Bypass -File C:\\\\redstackpro-setup.ps1\""
  })
}

# The offense Windows operator has no WinRM and is never provisioned by Ansible,
# so its operator kit (MobaXterm, browser, tools) and its hosts file ride a
# CustomScript extension. It is exclusive with the winrm extension above (a host
# is either a range Windows box or the ops operator, never both), so the VM never
# carries two CustomScript extensions. The script is base64 (it uses PowerShell
# here-strings), RSP_HOSTS names the range, and RSP_OPERATOR is the account whose
# profile the kit lands in. See operator_setup.ps1.
resource "azurerm_virtual_machine_extension" "operator_setup" {
  count                = (var.windows && var.operator_setup) ? 1 : 0
  name                 = "redstackpro-operator-setup"
  virtual_machine_id   = azurerm_windows_virtual_machine.this[0].id
  publisher            = "Microsoft.Compute"
  type                 = "CustomScriptExtension"
  type_handler_version = "1.10"

  settings = jsonencode({
    commandToExecute = "powershell -ExecutionPolicy Bypass -Command \"$env:RSP_OPERATOR='${var.operator_username}'; $env:RSP_HOSTS=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${base64encode(var.operator_hosts)}')); $env:RSP_SSH_KEY=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${base64encode(var.operator_ssh_key)}')); [IO.File]::WriteAllBytes('C:\\\\redstackpro-operator-setup.ps1',[Convert]::FromBase64String('${var.operator_setup_script_b64}')); powershell -ExecutionPolicy Bypass -File C:\\\\redstackpro-operator-setup.ps1\""
  })
}

output "private_address" {
  value = var.private_ip
}

output "public_address" {
  value = var.public_address ? azurerm_public_ip.this[0].ip_address : null
}

output "name" {
  value = lower(var.name)
}

# Auto stop. Azure has a purpose built per VM shutdown schedule, so like GCP
# this needs nothing of ours running and no credential anywhere: the platform
# stops the VM itself. Empty auto_stop_at means the canvas did not ask. See 0057.
#
# The time is HHmm with no separator, which is Azure's format, and the timezone
# is a WINDOWS timezone id ("UTC", "GMT Standard Time"), NOT the IANA name GCP
# takes. They agree on "UTC" and diverge on everything else, so anything other
# than UTC has to be given in Azure's vocabulary rather than translated silently.
variable "auto_stop_at" {
  description = "Daily shutdown time as HHmm, or empty for no schedule."
  type        = string
  default     = ""
}

variable "auto_stop_timezone" {
  description = "Windows timezone id the shutdown time is read in. Azure does not accept IANA names."
  type        = string
  default     = "UTC"
}

variable "auto_stop_enabled" {
  description = "Create the daily shutdown schedule. Static so count is known at plan; auto_stop_at is apply-computed in TTL mode and cannot gate count."
  type        = bool
  default     = false
}

resource "azurerm_dev_test_global_vm_shutdown_schedule" "this" {
  count              = var.auto_stop_enabled ? 1 : 0
  location           = var.location
  virtual_machine_id = var.windows ? azurerm_windows_virtual_machine.this[0].id : azurerm_linux_virtual_machine.this[0].id
  enabled            = true

  daily_recurrence_time = var.auto_stop_at
  timezone              = var.auto_stop_timezone

  # Required by the provider. Off: a range has no one to notify, and a webhook
  # would be another thing to stand up for a lab that is simply being turned off.
  notification_settings {
    enabled = false
  }
}
