# A VPC peering, plus the routes that make it carry traffic. Unlike GCP, which
# exchanges routes across a peering on its own, AWS leaves every route table
# pointing only at its own VPC, so each segment that should reach the peer needs
# a route to the peer CIDR through the connection. The compiler passes in the
# route table ids because they live in the per-subnet segment modules. See 0031.
#
# auto_accept is valid because both VPCs are in one account and one region, which
# is the shape every redStackPRO export has.

variable "name" {
  type        = string
  description = "Name tag for the peering connection."
}

variable "vpc_a" {
  type        = string
  description = "Id of the first VPC (the requester)."
}

variable "vpc_b" {
  type        = string
  description = "Id of the second VPC (the accepter)."
}

variable "cidr_a" {
  type        = string
  description = "CIDR of the first VPC, the destination for routes in the second."
}

variable "cidr_b" {
  type        = string
  description = "CIDR of the second VPC, the destination for routes in the first."
}

variable "route_tables_a" {
  type        = list(string)
  description = "Segment route tables in the first VPC, each routed to cidr_b."
}

variable "route_tables_b" {
  type        = list(string)
  description = "Segment route tables in the second VPC, each routed to cidr_a."
}

resource "aws_vpc_peering_connection" "this" {
  vpc_id      = var.vpc_a
  peer_vpc_id = var.vpc_b
  auto_accept = true

  tags = {
    Name        = lower(var.name)
    redstackpro = "true"
  }
}

# count, not for_each: the route table ids are segment-module outputs, unknown
# until apply, and for_each needs its keys known at plan. The number of tables is
# known (the segments are in the topology), so count over the list indexes works and
# plans cleanly. Same reason the segment NAT route turns on a plan-known value.
resource "aws_route" "a_to_b" {
  count                     = length(var.route_tables_a)
  route_table_id            = var.route_tables_a[count.index]
  destination_cidr_block    = var.cidr_b
  vpc_peering_connection_id = aws_vpc_peering_connection.this.id
}

resource "aws_route" "b_to_a" {
  count                     = length(var.route_tables_b)
  route_table_id            = var.route_tables_b[count.index]
  destination_cidr_block    = var.cidr_a
  vpc_peering_connection_id = aws_vpc_peering_connection.this.id
}
