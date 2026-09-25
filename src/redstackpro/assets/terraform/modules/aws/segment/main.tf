# A redStackPRO segment is a subnet inside exactly one network.
# egress and exposure are provider agnostic in the topology; this module renders
# them into AWS resources. See decision 0007.

# One zone for the whole export. Left to AWS, each subnet gets whichever zone it
# is given, so two applies of the same export differ, a redirector and the
# teamserver it fronts can land apart and pay cross zone transfer on ordinary
# traffic, and every private segment routes to a gateway that may be remote. A
# range is not a high availability workload, so predictable placement is worth
# more than spreading it.
resource "aws_subnet" "this" {
  vpc_id            = var.vpc_id
  cidr_block        = var.cidr
  availability_zone = var.availability_zone

  tags = {
    Name        = lower(var.name)
    redstackpro = "true"
  }
}

resource "aws_route_table" "this" {
  vpc_id = var.vpc_id

  tags = {
    Name = lower(var.name)
  }
}

resource "aws_route_table_association" "this" {
  subnet_id      = aws_subnet.this.id
  route_table_id = aws_route_table.this.id
}

# A public subnet routes 0.0.0.0/0 at the internet gateway; its addressed hosts
# (the jumpbox, the redirector) reach in and out directly. A subnet that routes
# through the NAT gateway instead must NOT also hold an internet-gateway route --
# one route table cannot point 0.0.0.0/0 at both -- so this is emitted only when
# the compiler did not ask for NAT. See 0021.
resource "aws_route" "internet" {
  count                  = var.nat ? 0 : 1
  route_table_id         = aws_route_table.this.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = var.internet_gateway_id
}

# Members with no public address still need outbound for package installation,
# and a gateway route is no use to a host that has no address.
#
# Whether any member lacks one is not visible from here: exposure is a ceiling,
# so a segment can permit public addresses and still hold hosts that took none.
# The compiler can see the members, so it decides and passes the answer in.
# See 0021.
#
# The count turns on var.nat alone, a value the compiler fixes at generate time.
# nat_gateway_id is a network-module output, unknown until apply, so testing it
# here would make the count itself unknown and break plan; it is not needed,
# because the compiler sets nat true only for a segment whose network builds the
# gateway (needs_nat is any segment_needs_nat), so the id is always present then.
resource "aws_route" "nat" {
  count                  = var.nat ? 1 : 0
  route_table_id         = aws_route_table.this.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = var.nat_gateway_id
}
