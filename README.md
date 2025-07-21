# PosHub AWS Infrastructure

Infrastructure AWS pour système POS avec Terraform.

## 🚀 Déploiement


# Ou avec Makefile
make deploy
```

## 🧪 Tests

```bash
# Tester l'infrastructure
make test

# Vérifier les logs CloudWatch
aws logs filter-log-events --log-group-name "/aws/lambda/poshub-dev-h" --filter-pattern "hello CW"
```

## 📋 Infrastructure

- **S3** : `poshub-dev-bucket`
- **IAM Role** : `poshub-lambda-role-h`
- **CloudWatch** : `/aws/lambda/poshub-dev-h`
- **SSM** : `/pos-h/api-key`

## 🎯 Commandes

```bash
make deploy    # Déployer
make test      # Tester
make plan      # Planifier
make output    # Outputs
```


