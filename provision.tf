resource "aws_key_pair" "sshkey" {
  key_name   = "sshkey"
  public_key = file(var.SSH_PUBLIC_KEY)
}

resource "aws_instance" "webapp" {
  subnet_id                   = aws_subnet.protected_a.id
  key_name                    = aws_key_pair.sshkey.key_name
  instance_type               = "t4g.nano"
  ami                         = var.AWS_AMI
  vpc_security_group_ids      = [aws_security_group.allow_all.id]
  associate_public_ip_address = true
  user_data                   = <<EOF
    yum install -y httpd
    systemctl start httpd
    systemctl enable httpd
    
    echo '<h1>Welcome to aws firewall demo<h1>' > /var/www/html/index.html
  EOF

  tags = {
    Name = "Webapp"
  }
}
