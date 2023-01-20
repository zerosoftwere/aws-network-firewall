///////// VPC

resource "aws_vpc" "demo" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    "Name" = "Demo Firewall VPC"
  }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.demo.id

  tags = {
    Name = "firewall igw"
  }
}

/////////// Firewall resources

resource "aws_subnet" "firewall" {
  vpc_id     = aws_vpc.demo.id
  cidr_block = "10.0.0.0/24"

  tags = {
    "Name" = "firewall sn"
  }
}

resource "aws_route_table" "firewall" {
  vpc_id = aws_vpc.demo.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = {
    Name = "firewall rt"
  }
}

resource "aws_route_table_association" "firewall_rt" {
  subnet_id      = aws_subnet.firewall.id
  route_table_id = aws_route_table.firewall.id
}

//////////// Stateless rule group

resource "aws_networkfirewall_rule_group" "stateless" {
  name     = "stateless"
  capacity = 100
  type     = "STATELESS"

  rule_group {
    rules_source {
      stateless_rules_and_custom_actions {
        stateless_rule {
          priority = 10
          rule_definition {
            actions = ["aws:drop"]
            match_attributes {
              protocols = [1]
              source {
                address_definition = "0.0.0.0/0"
              }

              destination {
                address_definition = "10.0.0.0/8"
              }
            }
          }
        }
        stateless_rule {
          priority = 20
          rule_definition {
            actions = ["aws:forward_to_sfe"]
            match_attributes {
              source {
                address_definition = "0.0.0.0/0"
              }

              destination {
                address_definition = "0.0.0.0/0"
              }
            }
          }
        }
      }
    }
  }
}

////////// Stateful rule grup

resource "aws_networkfirewall_rule_group" "statelful" {
  name     = "stateful"
  capacity = 100
  type     = "STATEFUL"
  rules    = <<EOF
pass tcp any any -> any 22 (msg:"Allow TCP 22"; sid:1000001; rev:1;)
pass http any any -> any any (http.host; dotprefix; content:".amazonaws.com"; endswith; msg:"Permit HTTP access to the web server"; sid:1000002; rev:1;)
pass ip ${aws_vpc.demo.cidr_block} any -> any any (msg:"Allow all outgoing traffic"; sid:1000003; rev:1;)
drop tcp any any -> any any (flow:established,to_server; msg:"Deny all other TCP traffic"; sid: 1000004; rev:1;)
EOF
}

data "aws_vpc_endpoint" "firewall" {
  vpc_id = aws_vpc.demo.id

  tags = {
    AWSNetworkFirewallManaged = "true"
    Firewall                  = aws_networkfirewall_firewall.firewall.arn
  }

  depends_on = [aws_networkfirewall_firewall.firewall]
}

/////////// Firewall policy

resource "aws_networkfirewall_firewall_policy" "fpolicy" {
  name = "fpolicy"

  firewall_policy {
    stateless_default_actions          = ["aws:pass"]
    stateless_fragment_default_actions = ["aws:drop"]

    stateless_rule_group_reference {
      priority     = 1
      resource_arn = aws_networkfirewall_rule_group.stateless.arn
    }

    stateful_rule_group_reference {
      resource_arn = aws_networkfirewall_rule_group.statelful.arn
    }
  }

  tags = {
    Name = "fpolicy"
  }
}

////////// Network firewall

resource "aws_networkfirewall_firewall" "firewall" {
  vpc_id = aws_vpc.demo.id
  name   = "firewall"

  subnet_mapping {
    subnet_id = aws_subnet.firewall.id
  }
  firewall_policy_arn = aws_networkfirewall_firewall_policy.fpolicy.arn

  tags = {
    Name = "Firewall"
  }
}

///////// Protected resources

resource "aws_subnet" "protected_a" {
  vpc_id     = aws_vpc.demo.id
  cidr_block = "10.0.1.0/24"

  tags = {
    "Name" = "protected a sn"
  }
}

resource "aws_subnet" "protected_b" {
  vpc_id     = aws_vpc.demo.id
  cidr_block = "10.0.2.0/24"

  tags = {
    "Name" = "protected b sn"
  }
}

resource "aws_route_table" "protected" {
  vpc_id = aws_vpc.demo.id

  route {
    cidr_block      = "0.0.0.0/0"
    vpc_endpoint_id = data.aws_vpc_endpoint.firewall.id
  }

  tags = {
    Name = "protected rt"
  }
}

resource "aws_route_table_association" "protected_rta" {
  subnet_id      = aws_subnet.protected_a.id
  route_table_id = aws_route_table.protected.id
}

resource "aws_route_table_association" "protected_rtb" {
  subnet_id      = aws_subnet.protected_b.id
  route_table_id = aws_route_table.protected.id
}

//////////// Internet gateway routes

resource "aws_route_table" "igw_rt" {
  vpc_id = aws_vpc.demo.id

  route {
    cidr_block      = aws_subnet.protected_a.cidr_block
    vpc_endpoint_id = data.aws_vpc_endpoint.firewall.id
  }

  route {
    cidr_block      = aws_subnet.protected_b.cidr_block
    vpc_endpoint_id = data.aws_vpc_endpoint.firewall.id
  }

  tags = {
    Name = "firewall igw rt"
  }
}

resource "aws_route_table_association" "igw_rta" {
  gateway_id     = aws_internet_gateway.igw.id
  route_table_id = aws_route_table.igw_rt.id
}

////// Security groups

resource "aws_security_group" "allow_all" {
  vpc_id = aws_vpc.demo.id
  name   = "Allow All"

  ingress {
    cidr_blocks = ["0.0.0.0/0"]
    to_port     = 0
    from_port   = 0
    protocol    = "-1"
  }

  egress {
    cidr_blocks = ["0.0.0.0/0"]
    to_port     = 0
    from_port   = 0
    protocol    = "-1"
  }

  tags = {
    Name = "All all"
  }
}
