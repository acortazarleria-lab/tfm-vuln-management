# DEMO — recurso deliberadamente inseguro para la evidencia del gate.
# CKV_AWS_24: SSH abierto a 0.0.0.0/0
resource "aws_security_group" "demo_inseguro" {
  name        = "demo-inseguro"
  description = "SSH abierto al mundo (inseguro a proposito, demo TFM)"
  vpc_id      = module.networking.vpc_id

  ingress {
    description = "SSH abierto - a corregir en este mismo PR"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = local.common_tags
}

# ENI de demo: adjunta el SG a un recurso para que el unico hallazgo
# sea el relevante (evita CKV2_AWS_5, security group huerfano).
resource "aws_network_interface" "demo" {
  subnet_id       = module.networking.private_compute_subnet_id
  security_groups = [aws_security_group.demo_inseguro.id]

  tags = local.common_tags
}
