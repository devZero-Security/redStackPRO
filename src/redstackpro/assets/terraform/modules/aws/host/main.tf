# Every redStackPRO host kind uses this module. The kind distinction is carried by
# inputs (image, public_address, instance_type) rather than by separate modules,
# because per kind host modules would be near identical copies. See 0015.

# An AMI id is per region and the region is a variable, so the image arrives as
# an owner and a name pattern and is resolved here.
data "aws_ami" "this" {
  most_recent = true
  owners      = [var.image_owner]

  filter {
    name   = "name"
    values = [var.image_name]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# One security group per host.
#
# This is the difference from the GCP module, which has no equivalent resource.
# GCP restricts a source by network tag, and a tag is a string that needs
# nothing to exist. An AWS rule references a security group by id, so the group
# has to be a resource here for the generated rules to point at it. See 0015.
resource "aws_security_group" "this" {
  name        = lower(var.name)
  vpc_id      = var.vpc_id
  description = "redStackPRO ${var.kind} ${var.name}"

  # Open at the group, decided by the route table. A segment with egress none
  # has no default route, so nothing leaves regardless of what this permits.
  # Same shape as the GCP backend.
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = lower(var.name)
    redstackpro = "true"
  }
}

resource "aws_instance" "this" {
  ami           = data.aws_ami.this.id
  instance_type = var.instance_type
  subnet_id     = var.subnet_id
  # Pinned when the topology locks this host to a specific address (a range on
  # GOAD's canonical octets, see 0055); null lets AWS assign one from the
  # subnet's range, the unchanged default.
  private_ip = var.private_ip != "" ? var.private_ip : null
  # Windows AMIs reject ed25519 key pairs on AWS, and a Windows host is reached
  # over WinRM with the lab password rather than SSH, so it takes no key pair.
  key_name               = var.windows ? null : var.key_name
  vpc_security_group_ids = [aws_security_group.this.id]
  # A host with no Elastic IP still needs egress. On a NAT-routed segment the NAT
  # handles it; on an internet-exposure (IGW-routed) segment there is no NAT, so an
  # address-less host takes an auto-assigned public IP for egress, the redStack way.
  associate_public_ip_address = var.public_address || var.auto_public_ip

  # Each box self-provisions at boot: a Windows host creates the operator account,
  # sets the shared lab password, and enables RDP; a Linux host creates the admin account,
  # sets the same password, and authorizes the Guacamole key. Neither needs the
  # configuration layer to reach in, which is the low-touch path. See 0001, 0019.
  user_data = var.windows ? templatefile("${path.module}/windows-setup.ps1.tftpl", {
    operator_username         = var.operator_username
    lab_password              = var.lab_password
    enable_winrm              = var.enable_winrm
    operator_setup            = var.operator_setup
    operator_setup_script_b64 = var.operator_setup_script_b64
    operator_hosts            = var.operator_hosts
    operator_ssh_key          = var.operator_ssh_key
    }) : templatefile("${path.module}/cloud-init.yaml.tftpl", {
    admin_username    = var.admin_username
    ssh_public_key    = var.ssh_public_key
    lab_password      = var.lab_password
    operator_username = var.operator_username
    guac_public_key   = var.guac_public_key
    guac_private_key  = var.guac_private_key
  })

  root_block_device {
    volume_size = var.disk_size_gb
    encrypted   = true
  }

  tags = {
    Name                = lower(var.name)
    redstackpro         = "true"
    redstackpro_kind    = var.kind
    redstackpro_node_id = var.node_id
  }
}

# A stable address for the hosts reached from outside, the jumpbox and the
# redirector, so a stop and start does not move them and DNS or a saved session
# keeps working. It replaces the auto-assigned public address on the instance.
resource "aws_eip" "this" {
  count    = var.elastic_ip ? 1 : 0
  instance = aws_instance.this.id
  domain   = "vpc"

  tags = {
    Name        = lower(var.name)
    redstackpro = "true"
  }
}
