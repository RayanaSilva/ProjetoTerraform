# Define o provedor AWS e configura a região como us-east-1.
provider "aws" {
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
  default     = "SeuNome"
}

#Gera uma chave privada RSA de 2048 bits para ser usada como par de chaves SSH.
resource "tls_private_key" "ec2_key" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

# Cria um par de chaves na AWS com a chave pública gerada pelo recurso tls_private_key.
resource "aws_key_pair" "ec2_key_pair" {
  key_name   = "${var.projeto}-${var.candidato}-key"
  public_key = tls_private_key.ec2_key.public_key_openssh
}

# Cria uma VPC com o CIDR 10.0.0.0/16, habilitando suporte para DNS e hostnames dentro da rede.
resource "aws_vpc" "main_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "${var.projeto}-${var.candidato}-vpc"
  }
}

# Cria uma sub-rede dentro da VPC na zona de disponibilidade us-east-1a com o bloco CIDR 10.0.1.0/24.
resource "aws_subnet" "main_subnet" {
  vpc_id            = aws_vpc.main_vpc.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "us-east-1a"

  tags = {
    Name = "${var.projeto}-${var.candidato}-subnet"
  }
}

# Anexa um gateway de internet à VPC para permitir a conectividade com a internet.
resource "aws_internet_gateway" "main_igw" {
  vpc_id = aws_vpc.main_vpc.id

  tags = {
    Name = "${var.projeto}-${var.candidato}-igw"
  }
}

# Cria uma tabela de rotas para a VPC, permitindo rotas para a internet via o gateway de internet.
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

# Associa a tabela de rotas criada à sub-rede.
resource "aws_route_table_association" "main_association" {
  subnet_id      = aws_subnet.main_subnet.id
  route_table_id = aws_route_table.main_route_table.id

  tags = {
    Name = "${var.projeto}-${var.candidato}-route_table_association"
  }
}

# Cria um grupo de segurança que permite:
# Entrada de tráfego SSH (porta 22) de qualquer lugar (IPv4 e IPv6).
# Saída de todo o tráfego (todas as portas e protocolos) para qualquer destino.
resource "aws_security_group" "main_sg" {
  name        = "${var.projeto}-${var.candidato}-sg"
  description = "Permitir SSH apenas de IP específico e bloquear portas comuns de ataque"
  vpc_id      = aws_vpc.main_vpc.id

  # Regras de entrada (permitir SSH apenas de um IP específico)
  ingress {
    description      = "Allow SSH from specific IP"
    from_port        = 22
    to_port          = 22
    protocol         = "tcp"
    cidr_blocks      = ["${var.allowed_ssh_ip}"]  # Substituir pelo IP confiável
  }

  # Não abrir portas comumente atacadas como 3389 (RDP), 23 (Telnet), etc.

  # Regras de saída (permitir todo tráfego de saída)
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

# Cria uma instância EC2 do tipo t2.micro utilizando a AMI do Debian 12.
# A instância é configurada com um disco de 20 GB.
# Um script de inicialização (user_data) é executado para atualizar e atualizar os pacotes do # sistema assim que a instância for criada.
resource "aws_instance" "debian_ec2" {
  ami             = data.aws_ami.debian12.id
  instance_type   = "t2.micro"
  subnet_id       = aws_subnet.main_subnet.id
  key_name        = aws_key_pair.ec2_key_pair.key_name
  security_groups = [aws_security_group.main_sg.name]

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
              EOF

  tags = {
    Name = "${var.projeto}-${var.candidato}-ec2"
  }
}

#  Exibe a chave privada gerada pelo Terraform.
output "private_key" {
  description = "Chave privada para acessar a instância EC2"
  value       = tls_private_key.ec2_key.private_key_pem
  sensitive   = true
}

# Exibe o endereço IP público da instância EC2.
output "ec2_public_ip" {
  description = "Endereço IP público da instância EC2"
  value       = aws_instance.debian_ec2.public_ip
}

#
resource "aws_secretsmanager_secret" "ec2_private_key_secret" {
  name        = "${var.projeto}-${var.candidato}-ec2-private-key"
  description = "Chave privada para acessar a instância EC2"
}

resource "aws_secretsmanager_secret_version" "ec2_private_key_secret_version" {
  secret_id     = aws_secretsmanager_secret.ec2_private_key_secret.id
  secret_string = tls_private_key.ec2_key.private_key_pem
}

# Remover o output da chave privada, para não expor a chave em outputs:
 output "private_key" {
   description = "Chave privada para acessar a instância EC2"
   value       = tls_private_key.ec2_key.private_key_pem
   sensitive   = true
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

# Este recurso anexa a política gerenciada da AWS chamada CloudWatchAgentServerPolicy à função IAM (role) atribuída à instância EC2. 
# Isso permite que o CloudWatch Agent dentro da instância envie métricas e logs para o CloudWatch.
resource "aws_iam_role_policy_attachment" "ec2_cloudwatch_policy" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

# O perfil da instância (instance profile) associa a função IAM à instância EC2, garantindo que a instância tenha as permissões 
# necessárias para acessar serviços da AWS, como o CloudWatch.
resource "aws_iam_instance_profile" "ec2_instance_profile" {
  name = "${var.projeto}-${var.candidato}-ec2-instance-profile"
  role = aws_iam_role.ec2_role.name
}

resource "aws_instance" "debian_ec2" {
  # Especifica o ID da imagem AMI para criar a instância EC2 (Debian 12 no caso).
  ami = data.aws_ami.debian12.id

  # Define o tipo da instância EC2 (t2.micro, uma das opções de uso gratuito da AWS).
  instance_type = "t2.micro"

  # Define a subnet onde a instância será criada.
  subnet_id = aws_subnet.main_subnet.id

  # Especifica o nome da chave SSH para acessar a instância.
  key_name = aws_key_pair.ec2_key_pair.key_name

  # Associa a instância a um ou mais grupos de segurança (security groups).
  security_groups = [aws_security_group.main_sg.name]

  # Associa um perfil de instância IAM para que a instância EC2 tenha permissões, 
  # como enviar logs para o CloudWatch.
  iam_instance_profile = aws_iam_instance_profile.ec2_instance_profile.name

  # Garante que a instância receberá um endereço IP público.
  associate_public_ip_address = true

  # Configuração do disco raiz da instância.
  root_block_device {
    # Tamanho do disco em GB.
    volume_size = 20

    # Tipo do disco (gp2 - SSD padrão da AWS).
    volume_type = "gp2"

    # Define que o disco será apagado quando a instância for terminada.
    delete_on_termination = true
  }

  # Script de inicialização (user_data) que será executado quando a instância for iniciada.
  user_data = <<-EOF
              # Atualiza o sistema.
              apt-get update -y
              apt-get upgrade -y

              # Instala o servidor web Nginx.
              apt-get install nginx -y
              systemctl start nginx
              systemctl enable nginx

              # Instala o agente do CloudWatch.
              apt-get install -y amazon-cloudwatch-agent

              # Cria o arquivo de configuração para o CloudWatch Agent para enviar logs.
              cat <<EOT >> /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json
              {
                "agent": {
                  "metrics_collection_interval": 60,   # Intervalo de coleta de métricas.
                  "logfile": "/var/log/messages",      # Caminho do arquivo de log.
                  "region": "us-east-1"               # Região AWS.
                },
                "logs": {
                  "logs_collected": {
                    "files": {
                      "collect_list": [
                        {
                          "file_path": "/var/log/syslog",       # Coleta logs do sistema.
                          "log_group_name": "/aws/ec2/${var.projeto}-${var.candidato}/syslog",  # Nome do grupo de logs.
                          "log_stream_name": "{instance_id}"     # Nome do stream de logs.
                        },
                        {
                          "file_path": "/var/log/nginx/access.log",   # Coleta logs de acesso do Nginx.
                          "log_group_name": "/aws/ec2/${var.projeto}-${var.candidato}/nginx_access",  # Nome do grupo de logs.
                          "log_stream_name": "{instance_id}"     # Nome do stream de logs.
                        }
                      ]
                    }
                  }
                }
              }
              EOT

              # Inicia o agente do CloudWatch para coletar e enviar logs.
              systemctl start amazon-cloudwatch-agent
              EOF

  # Adiciona tags à instância, úteis para organização e identificação.
  tags = {
    Name = "${var.projeto}-${var.candidato}-ec2"
  }
}
