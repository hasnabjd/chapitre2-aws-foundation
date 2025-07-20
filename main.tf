# PosHub AWS Infrastructure
# Infrastructure AWS pour système POS avec Terraform

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "eu-north-1"  # Région AWS
}

# Data sources pour récupérer les informations AWS
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# Policy S3PosDevRW-h
resource "aws_iam_policy" "S3PosDevRW-h" {
  name        = "S3PosDevRW-h"
  description = "Policy to allow read/write access to poshub-dev-bucket"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect   = "Allow",
        Action   = [
          "s3:GetObject",
          "s3:PutObject"
        ],
        Resource = "arn:aws:s3:::poshub-dev-bucket/*"
      }
    ]
  })
}

# Outputs pour afficher les informations importantes
output "account_id" {
  description = "ID du compte AWS"
  value       = data.aws_caller_identity.current.account_id
}

output "region" {
  description = "Région AWS utilisée"
  value       = data.aws_region.current.name
}

output "policy_arn" {
  description = "ARN de la policy S3PosDevRW-h"
  value       = aws_iam_policy.S3PosDevRW-h.arn
}