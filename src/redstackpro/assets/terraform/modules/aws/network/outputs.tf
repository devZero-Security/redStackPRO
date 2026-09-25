output "id" {
  value = aws_vpc.this.id
}

output "internet_gateway_id" {
  value = aws_internet_gateway.this.id
}

# Null when no segment asked for outbound routing, which is what the segment
# module checks before it writes a default route.
output "nat_gateway_id" {
  value = try(aws_nat_gateway.this[0].id, null)
}

# Where an addressed host goes, since a NAT-routed segment subnet cannot carry one.
# Null when nothing asked for a public subnet.
output "public_subnet_id" {
  value = try(aws_subnet.public[0].id, null)
}

# The route table serving the public subnet. A peering has to route from here
# too, not only from the segment tables: a public-addressed host lives in this
# subnet (see public_subnet_id), so without a peer route it can reach the
# internet and every local address but nothing across the peering. That is how
# an ops jumpbox lost its redirector. Null when there is no public subnet.
output "public_route_table_id" {
  value = try(aws_route_table.public[0].id, null)
}
