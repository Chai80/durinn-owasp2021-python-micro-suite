# GT: IAC_TF_01_START
# Terraform example intentionally misconfigured for benchmarking IaC scanners.
#
# Issue: Security group allows SSH (22) from anywhere (0.0.0.0/0).

resource "aws_security_group" "allow_ssh_from_anywhere" {
  name        = "allow_ssh_from_anywhere"
  description = "(Benchmark) Allow inbound SSH from anywhere"

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
# GT: IAC_TF_01_END
