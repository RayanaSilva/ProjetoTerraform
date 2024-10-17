# Projeto Terraform - Provisionamento de Infraestrutura AWS
Este repositório contém um conjunto de scripts Terraform para provisionar uma infraestrutura básica na AWS, incluindo uma instância EC2 com uma configuração de rede e segurança, além de integração com o CloudWatch para monitoramento de logs.

## Descrição Técnica

### Tarefa 1
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

#### Arquivo [main.tf]([https://](https://github.com/RayanaSilva/ProjetoTerraform)) Modificado.

### Tarefa 2
Melhorias implementadas:

1. **Segurança da chave privada:**
   A chave privada agora é armazenada no AWS Secrets Manager em vez de ser exposta diretamente no output do Terraform, garantindo maior segurança.
2. **Monitoramento aprimorado:**
   A instância EC2 agora tem o Amazon CloudWatch Agent instalado e configurado para monitorar os logs do sistema e do Nginx, enviando-os para o CloudWatch, facilitando o acompanhamento de métricas e logs da instância.
3. **IAM Role e CloudWatch Integration:**
   Foi configurada uma role do IAM associada à instância EC2, permitindo que a instância utilize o CloudWatch Agent para envio de logs, integrando o monitoramento à infraestrutura.
