terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.16"
    }
  }

  required_version = ">= 1.2.0"
}

# Define o provedor AWS e configura a região como us-east-1.
provider "aws" {
  # Utilizado para controlar o perfil que tenha acesso as funcionalidades de criação de EC2
  profile = "ray-terraform"
  region = "us-east-1"
}

# Definem as variáveis projeto e candidato com valores padrão para o nome do projeto (VExpenses) e do candidato (SeuNome), utilizados para nomear diversos recursos.
variable "projeto" {
  description = "Nome do projeto"
  type        = string
  default     = "VExpenses"
}

variable "candidato" {
  description = "Nome do candidato"
  type        = string
  default     = "rayana"
}

resource "tls_private_key" "ec2_key" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "aws_key_pair" "ec2_key_pair" {
  key_name   = "${var.projeto}-${var.candidato}-key"
  public_key = tls_private_key.ec2_key.public_key_openssh
}

output "private_key" {
  description = "The private key generated for EC2"
  value       = tls_private_key.ec2_key.private_key_pem
  sensitive   = true  # Mantém a chave privada como sensível, não será registrada no Terraform state file
}

resource "local_file" "private_key_pem_file" {
  content  = tls_private_key.ec2_key.private_key_pem
  filename = "./private_key.pem"
}

resource "aws_vpc" "main_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "${var.projeto}-${var.candidato}-vpc"
  }
}

resource "aws_subnet" "main_subnet" {
  vpc_id            = aws_vpc.main_vpc.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "us-east-1a"

  tags = {
    Name = "${var.projeto}-${var.candidato}-subnet"
  }
}

resource "aws_internet_gateway" "main_igw" {
  vpc_id = aws_vpc.main_vpc.id

  tags = {
    Name = "${var.projeto}-${var.candidato}-igw"
  }
}

resource "aws_route_table" "main_route_table" {
  vpc_id = aws_vpc.main_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main_igw.id
  }

  tags = {
    Name = "${var.projeto}-${var.candidato}-route_table"
  }
}

resource "aws_route_table_association" "main_association" {
  subnet_id      = aws_subnet.main_subnet.id
  route_table_id = aws_route_table.main_route_table.id
}

resource "aws_security_group" "main_sg" {
  name        = "${var.projeto}-${var.candidato}-sg"
  description = "Permitir SSH apenas de IP especifico e bloquear portas comuns de ataque"
  vpc_id      = aws_vpc.main_vpc.id

   ingress {
    description      = "Allow SSH from specific IP"
    from_port        = 22
    to_port          = 22
    protocol         = "tcp"
    cidr_blocks      = ["193.186.4.202/32"]  # Substituir pelo IP confiável
  }

  egress {
    description      = "Allow all outbound traffic"
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = {
    Name = "${var.projeto}-${var.candidato}-sg"
  }
}

# Busca a AMI mais recente do Debian 12 (amd64) utilizando o dono da AMI (679593333241) e filtros como tipo de virtualização HVM.
data "aws_ami" "debian12" {
  most_recent = true

  filter {
    name   = "name"
    values = ["debian-12-amd64-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  owners = ["679593333241"]
}

output "ec2_public_ip" {
  description = "Endereço IP público da instância EC2"
  value       = aws_instance.debian_ec2.public_ip
}

resource "aws_secretsmanager_secret" "ec2_private_key_secret" {
  name        = "${var.projeto}-${var.candidato}-ec2-private-key"
  description = "Chave privada para acessar a instância EC2"
}

resource "aws_secretsmanager_secret_version" "ec2_private_key_secret_version" {
  secret_id     = aws_secretsmanager_secret.ec2_private_key_secret.id
  secret_string = tls_private_key.ec2_key.private_key_pem
}

#Criar uma role IAM com permissões para a instância EC2 enviar logs para o CloudWatch
resource "aws_iam_role" "ec2_role" {
  name = "${var.projeto}-${var.candidato}-ec2-role"

  assume_role_policy = <<EOF
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Principal": {
          "Service": "ec2.amazonaws.com"
        },
        "Action": "sts:AssumeRole"
      }
    ]
  }
  EOF
}

resource "aws_iam_role_policy_attachment" "ec2_cloudwatch_policy" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

resource "aws_iam_instance_profile" "ec2_instance_profile" {
  name = "${var.projeto}-${var.candidato}-ec2-instance-profile"
  role = aws_iam_role.ec2_role.name
}

# Cria uma instância EC2 do tipo t2.micro utilizando a AMI do Debian 12.
# A instância é configurada com um disco de 20 GB.
# Um script de inicialização (user_data) é executado para atualizar e atualizar os pacotes do # sistema assim que a instância for criada.
resource "aws_instance" "debian_ec2" {
  depends_on = [aws_security_group.main_sg]
  ami             = data.aws_ami.debian12.id
  instance_type   = "t2.micro"
  subnet_id       = aws_subnet.main_subnet.id
  key_name        = aws_key_pair.ec2_key_pair.key_name
  security_groups = [aws_security_group.main_sg.id]
  iam_instance_profile = aws_iam_instance_profile.ec2_instance_profile.name

  associate_public_ip_address = true

  root_block_device {
    volume_size           = 20
    volume_type           = "gp2"
    delete_on_termination = true
  }

  user_data = <<-EOF
              #!/bin/bash
              apt-get update -y
              apt-get upgrade -y
              apt-get install nginx -y
              systemctl start nginx
              systemctl enable nginx

              apt-get install -y amazon-cloudwatch-agent

              cat <<EOT >> /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json
              {
                "agent": {
                  "metrics_collection_interval": 60,
                  "logfile": "/var/log/messages",
                  "region": "us-east-1"
                },
                "logs": {
                  "logs_collected": {
                    "files": {
                      "collect_list": [
                        {
                          "file_path": "/var/log/syslog",
                          "log_group_name": "/aws/ec2/${var.projeto}-${var.candidato}/syslog",
                          "log_stream_name": "{instance_id}"
                        },
                        {
                          "file_path": "/var/log/nginx/access.log",
                          "log_group_name": "/aws/ec2/${var.projeto}-${var.candidato}/nginx_access",
                          "log_stream_name": "{instance_id}"
                        }
                      ]
                    }
                  }
                }
              }
              EOT

              systemctl start amazon-cloudwatch-agent
              EOF

  tags = {
    Name = "${var.projeto}-${var.candidato}-ec2"
  }
}
