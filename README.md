# PosHub AWS Infrastructure

Ce projet configure l'infrastructure AWS pour un système POS (Point of Sale) en utilisant Terraform.

## 🎯 Objectifs d'Apprentissage

### 1. IAM 
- Création du role de read/write sur S3 bucket

### 2. Lambda Function → poshub-lambda-role
    ↓
├── CloudWatch (logs)
├── S3 (stockage données)
└── SSM Parameter Store (configurations)

1. **Configuration Terraform** - IAM, S3, CloudWatch Log Group
2. **Déploiement** - Infrastructure AWS
3. **Log Group CloudWatch** - `/aws/lambda/poshub-dev-h` (30 jours)
4. **Tests** - Vérification complète


### 🚀 Commandes
```bash
make deploy    # Déployer l'infrastructure
make test      # Tester tous les composants
make plan      # Vérifier les changements
make output    # Voir les outputs
```