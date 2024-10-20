# Projeto Terraform - Provisionamento de Infraestrutura AWS
Este repositório contém um conjunto de scripts Terraform para provisionar uma infraestrutura básica na AWS, incluindo uma instância EC2 com uma configuração de rede e segurança, além de integração com o CloudWatch para monitoramento de logs.

## Descrição Técnica

Este código provisiona os seguintes recursos na AWS:

1. **VPC (Virtual Private Cloud):**
   Rede isolada com um CIDR block de 10.0.0.0/16.
2. **Subnet:**
   Subrede com um CIDR block de 10.0.1.0/24, dentro da VPC provisionada.
3. **Internet Gateway:**
   Conecta a VPC à internet, permitindo que instâncias na VPC acessem a internet.
4. **Tabela de Roteamento:**
   Define a rota padrão (0.0.0.0/0) para enviar o tráfego de saída para o Internet Gateway.
5. **Security Group:**
   Regras de segurança para permitir acesso SSH (porta 22) de um IP específico e permitir todo o tráfego de saída.
6. **EC2 Instance:**
   Instância Debian 12 (t2.micro) com um volume de 20GB.
   Configurações incluem instalação do Nginx e do Amazon CloudWatch Agent para monitoramento de logs.
7. **Chave SSH:**
   Chave RSA de 2048 bits gerada dinamicamente para permitir acesso seguro à instância.
8. **AWS Secrets Manager:**
   Armazena a chave privada gerada no AWS Secrets Manager para acesso seguro.
9. **IAM Role:**
    Permissão para que a instância EC2 use o CloudWatch Agent, facilitando o envio de logs.

#### Arquivo [main.tf]([https://]([https://github.com/RayanaSilva/ProjetoTerraform/](https://github.com/RayanaSilva/ProjetoTerraform/blob/main/main.tf))) Modificado.

Melhorias implementadas:

1. **Segurança da chave privada:**
   A chave privada agora é armazenada no AWS Secrets Manager em vez de ser exposta diretamente no output do Terraform, garantindo maior segurança.
2. **Monitoramento aprimorado:**
   A instância EC2 agora tem o Amazon CloudWatch Agent instalado e configurado para monitorar os logs do sistema e do Nginx, enviando-os para o CloudWatch, facilitando o acompanhamento de métricas e logs da instância.
3. **IAM Role e CloudWatch Integration:**
   Foi configurada uma role do IAM associada à instância EC2, permitindo que a instância utilize o CloudWatch Agent para envio de logs, integrando o monitoramento à infraestrutura.


## Pré-requisitos

- **Terraform**: versão >= 1.2.0
- **AWS CLI** configurada com permissões adequadas
- **Credenciais AWS** com acesso para criar EC2, VPC e outros recursos

## Variáveis

- `projeto`: Nome do projeto (padrão: `VExpenses`)
- `candidato`: Nome do candidato (padrão: `rayana`)

## Comandos para Executar o Projeto

1. Clone o repositório:

   ```bash
   git clone https://github.com/RayanaSilva/ProjetoTerraform.git
   cd ProjetoTerraform

2. Execute os comandos para aplicar as configurações:

   ```bash
   terraform init
   terraform plan
   terraform apply

## Estrutura
   - aws_vpc: Criação da VPC e sub-rede.
      ```
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
      }

   - aws_security_group: Definição de regras de segurança para tráfego SSH.
     ```
     # Cria um grupo de segurança que permite:
      # Entrada de tráfego SSH (porta 22) de qualquer lugar (IPv4 e IPv6).
      # Saída de todo o tráfego (todas as portas e protocolos) para qualquer destino.
      resource "aws_security_group" "main_sg" {
        name        = "${var.projeto}-${var.candidato}-sg"
        description = "Permitir SSH apenas de IP especifico e bloquear portas comuns de ataque"
        vpc_id      = aws_vpc.main_vpc.id

        # Regras de entrada (permitir SSH apenas de um IP específico)
        ingress {
          description      = "Allow SSH from specific IP"
          from_port        = 22
          to_port          = 22
          protocol         = "tcp"
          cidr_blocks      = ["193.186.4.202/32"]  # Substituir pelo IP confiável
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

   - tls_private_key: Geração de par de chaves para acesso seguro à instância.
     ```
     # Gera uma chave privada RSA de 2048 bits para ser usada como par de chaves SSH.
      resource "tls_private_key" "ec2_key" {
        algorithm = "RSA"
        rsa_bits  = 2048
      }

      # Cria um par de chaves na AWS com a chave pública gerada pelo recurso tls_private_key.
      resource "aws_key_pair" "ec2_key_pair" {
        key_name   = "${var.projeto}-${var.candidato}-key"
        public_key = tls_private_key.ec2_key.public_key_openssh
      }

      # Exibir a chave privada
      output "private_key" {
        description = "The private key generated for EC2"
        value       = tls_private_key.ec2_key.private_key_pem
        sensitive   = true  # Mantém a chave privada como sensível, não será registrada no Terraform state file
      }

      # Salvar a chave privada PEM em um arquivo local
      resource "local_file" "private_key_pem_file" {
        content  = tls_private_key.ec2_key.private_key_pem
        filename = "./private_key.pem"
      }
     
   - aws_iam_role: Configuração de permissões para EC2 enviar logs para o CloudWatch.
     ```
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

   - aws_instance: Configuração da instância EC2 com Debian, CloudWatch e NGINX.
      ```
      # Cria uma instância EC2 do tipo t2.micro utilizando a AMI do Debian 12.
      # A instância é configurada com um disco de 20 GB.
      # Um script de inicialização (user_data) é executado para atualizar e atualizar os pacotes do # sistema assim que a instância for criada.
      resource "aws_instance" "debian_ec2" {
        depends_on = [aws_security_group.main_sg]
        # Especifica o ID da imagem AMI para criar a instância EC2 (Debian 12 no caso).
        ami             = data.aws_ami.debian12.id
        # Define o tipo da instância EC2 (t2.micro, uma das opções de uso gratuito da AWS).
        instance_type   = "t2.micro"
        # Define a subnet onde a instância será criada.
        subnet_id       = aws_subnet.main_subnet.id
        # Especifica o nome da chave SSH para acessar a instância.
        key_name        = aws_key_pair.ec2_key_pair.key_name
        # Associa a instância a um ou mais grupos de segurança (security groups).
        security_groups = [aws_security_group.main_sg.id]
        # Associa um perfil de instância IAM para que a instância EC2 tenha permissões, como enviar logs para o CloudWatch.
        iam_instance_profile = aws_iam_instance_profile.ec2_instance_profile.name

        # Garante que a instância receberá um endereço IP público.
        associate_public_ip_address = true

        # Configuração do disco raiz da instância.
        root_block_device {
          # Tamanho do disco em GB.
          volume_size           = 20
          # Tipo do disco (gp2 - SSD padrão da AWS).
          volume_type           = "gp2"
          # Define que o disco será apagado quando a instância for terminada.
          delete_on_termination = true
        }

        # Script de inicialização (user_data) que será executado quando a instância for iniciada.
        user_data = <<-EOF
                    #!/bin/bash
                    apt-get update -y
                    apt-get upgrade -y
                    apt-get install nginx -y
                    systemctl start nginx
                    systemctl enable nginx

                    # Instalação do CloudWatch Agent
                    apt-get install -y amazon-cloudwatch-agent

                    # Configuração do CloudWatch Agent para enviar logs
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

                    # Inicia o agente do CloudWatch para coletar e enviar logs.
                    systemctl start amazon-cloudwatch-agent
                    EOF

        # Adiciona tags à instância, úteis para organização e identificação.
        tags = {
          Name = "${var.projeto}-${var.candidato}-ec2"
        }
      }

## Contribuição
Sinta-se à vontade para sugerir melhorias ou abrir PRs!
