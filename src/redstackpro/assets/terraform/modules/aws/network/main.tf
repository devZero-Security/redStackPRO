# A redStackPRO network is a routing domain. Members reach each other privately.

resource "aws_vpc" "this" {
  cidr_block           = var.cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name        = lower(var.name)
    redstackpro = "true"
  }
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id

  tags = {
    Name = "${lower(var.name)}-igw"
  }
}

# The one public subnet: default route straight to the internet gateway. Two
# different things need it, and AWS routes per SUBNET rather than per instance, so
# they have to share it.
#
#   1. A NAT gateway has to sit in a public subnet to reach the internet at all.
#      GCP's Cloud NAT attaches to the network and needs no subnet, so this exists
#      only because the provider does it differently.
#   2. Any host that took a public address. On GCP a jumpbox keeps its external
#      address inside the range subnet, because Cloud NAT serves only instances
#      WITHOUT one, so routing is effectively per instance. On AWS a subnet has a
#      single route table: point it at the NAT for the range's internal hosts and
#      an addressed host in that same subnet becomes unreachable inbound, because
#      its replies go to the NAT and die. The range's only entry point silently
#      stops answering. So addressed hosts move here instead.
#
# The range comes from the compiler, which picks one no segment occupies.

resource "aws_subnet" "public" {
  count                   = (var.create_nat || var.create_public_subnet) ? 1 : 0
  vpc_id                  = aws_vpc.this.id
  cidr_block              = var.public_subnet_cidr
  availability_zone       = var.availability_zone
  map_public_ip_on_launch = false

  tags = {
    Name = "${lower(var.name)}-public"
  }
}

resource "aws_route_table" "public" {
  count  = (var.create_nat || var.create_public_subnet) ? 1 : 0
  vpc_id = aws_vpc.this.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.this.id
  }

  tags = {
    Name = "${lower(var.name)}-public"
  }
}

resource "aws_route_table_association" "public" {
  count          = (var.create_nat || var.create_public_subnet) ? 1 : 0
  subnet_id      = aws_subnet.public[0].id
  route_table_id = aws_route_table.public[0].id
}

resource "aws_eip" "nat" {
  count  = var.create_nat ? 1 : 0
  domain = "vpc"

  tags = {
    Name = "${lower(var.name)}-nat"
  }
}

resource "aws_nat_gateway" "this" {
  count         = var.create_nat ? 1 : 0
  allocation_id = aws_eip.nat[0].id
  subnet_id     = aws_subnet.public[0].id

  tags = {
    Name = "${lower(var.name)}-nat"
  }

  depends_on = [aws_internet_gateway.this]
}
