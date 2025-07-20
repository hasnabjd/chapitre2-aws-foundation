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

# IAM Role for Lambda function with trust policy
# This role allows AWS Lambda service to assume it for executing functions

resource "aws_iam_role" "poshub_lambda_role" {
  name = "poshub-lambda-role-h"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name        = "poshub-lambda-role-h"
    Environment = "development"
    Project     = "poshub"
  }
}

# Policy for CloudWatch Logs permissions
# Allows Lambda function to write logs to CloudWatch for monitoring and debugging
resource "aws_iam_policy" "cloudwatch_logs_policy" {
  name        = "CloudWatchLogsWrite-h"
  description = "Policy to allow Lambda function to write logs to CloudWatch"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/*"
      }
    ]
  })
}

# Policy for SSM Parameter Store access
# Allows Lambda function to retrieve configuration parameters and secrets
resource "aws_iam_policy" "ssm_parameter_policy" {
  name        = "SSMParameterPolicy-h"
  description = "Policy to allow Lambda function to read SSM parameters"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ssm:GetParameter",
          "ssm:GetParameters"
        ]
        Resource = "arn:aws:ssm:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:parameter/*"
      }
    ]
  })
}

# CloudWatch Log Group for Lambda function
# This log group will store all logs from the Lambda function with 30-day retention
resource "aws_cloudwatch_log_group" "poshub_lambda_log_group" {
  name              = "/aws/lambda/poshub-dev-h"
  retention_in_days = 30

  tags = {
    Name        = "poshub-lambda-log-group-h"
    Environment = "development"
    Project     = "poshub"
  }
}

# Attach policies to the Lambda role
# This connects all the necessary permissions to the role

resource "aws_iam_role_policy_attachment" "lambda_cloudwatch_attachment" {
  role       = aws_iam_role.poshub_lambda_role.name
  policy_arn = aws_iam_policy.cloudwatch_logs_policy.arn
}

resource "aws_iam_role_policy_attachment" "lambda_s3_attachment" {
  role       = aws_iam_role.poshub_lambda_role.name
  policy_arn = aws_iam_policy.S3PosDevRW-h.arn
}

resource "aws_iam_role_policy_attachment" "lambda_ssm_attachment" {
  role       = aws_iam_role.poshub_lambda_role.name
  policy_arn = aws_iam_policy.ssm_parameter_policy.arn
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

# Additional outputs for the new Lambda role
output "lambda_role_arn" {
  description = "ARN of the poshub-lambda-role-h"
  value       = aws_iam_role.poshub_lambda_role.arn
}

output "lambda_role_name" {
  description = "Name of the poshub-lambda-role-h"
  value       = aws_iam_role.poshub_lambda_role.name
}

output "lambda_log_group_arn" {
  description = "ARN of the CloudWatch log group for Lambda function"
  value       = aws_cloudwatch_log_group.poshub_lambda_log_group.arn
}

output "lambda_log_group_name" {
  description = "Name of the CloudWatch log group for Lambda function"
  value       = aws_cloudwatch_log_group.poshub_lambda_log_group.name
}