output "private_address" {
  value = aws_instance.this.private_ip
}

output "public_address" {
  # The Elastic IP when this host has one (the jumpbox and the redirector),
  # otherwise the auto-assigned public address every host holds for outbound.
  value = try(aws_eip.this[0].public_ip, aws_instance.this.public_ip, null)
}

output "name" {
  value = aws_instance.this.tags["Name"]
}

# What the generated firewall rules point at. GCP has no equivalent, because
# there a rule names a network tag rather than a resource. See 0015.
output "security_group_id" {
  value = aws_security_group.this.id
}

# What the auto-stop scheduler names. AWS has no per-instance schedule the way
# GCP has a resource policy, so the stop is one EventBridge schedule that calls
# ec2:StopInstances with an explicit list of ids. See 0057.
output "instance_id" {
  value = aws_instance.this.id
}
