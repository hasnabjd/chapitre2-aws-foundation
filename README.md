# PosHub AWS Infrastructure

Ce projet configure l'infrastructure AWS pour un système POS (Point of Sale) en utilisant Terraform. Il suit une approche modulaire et répond aux exigences d'apprentissage AWS IAM.

## 🎯 Objectifs d'Apprentissage

### 1. IAM – Bases Indispensables

#### 📖 Lecture Recommandée
Commencez par lire :
- [AWS IAM Primer (officiel)](https://docs.aws.amazon.com/IAM/latest/UserGuide/introduction.html)

Cela vous aidera à comprendre :
- **Les Policies** : Documents JSON qui définissent les permissions
- **Les Roles** : Identités temporaires que peuvent assumer les services AWS
- **Les Principals** : Qui peut faire quoi (utilisateurs, services, etc.)
- **Les Trust Policies** : Qui peut assumer un rôle

#### 📘 Exercice : Créer une Policy Personnalisée
**Nom** : `S3PosDevRW`  
**Permissions** : `s3:GetObject` et `s3:PutObject`  
**Bucket cible** : `poshub-dev-bucket`

```hcl
resource "aws_iam_policy" "S3PosDevRW" {
  name        = "S3PosDevRW"
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
```

### 2. Rôle Lambda

**Nom du rôle** : `poshub-lambda-role`  
**Trust** : Lambda (`lambda.amazonaws.com`)  
**Policies à attacher** :
- S3PosDevRW (ci-dessus)
- Accès limité CloudWatch (écriture uniquement)
- Accès SSM GetParameter pour secrets

```hcl
resource "aws_iam_role" "lambda_role" {
  name = "poshub-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Principal = {
          Service = "lambda.amazonaws.com"
        },
        Action = "sts:AssumeRole"
      }
    ]
  })
}
```

### 3. CloudWatch Logging

**Log Group** : `/aws/lambda/poshub-dev`  
**Retention** : 30 jours

```hcl
resource "aws_cloudwatch_log_group" "lambda_log_group" {
  name              = "/aws/lambda/poshub-dev"
  retention_in_days = 30
}
```

### 4. Gestion des Secrets

Stocker la clé API dans SSM Parameter Store sous forme sécurisée.

```hcl
resource "aws_ssm_parameter" "api_key" {
  name        = "/poshub/api-key"
  type        = "SecureString"
  value       = "ton-api-key-ici"
  description = "Clé API externe pour POSHub"
}
```

### 5. Test avec Python (boto3)

Dans `verify_aws_setup.py` :

```python
import boto3

ssm = boto3.client('ssm')
param = ssm.get_parameter(
    Name='/poshub/api-key',
    WithDecryption=True
)
print("API Key:", param['Parameter']['Value'])
```

## 📁 Organisation du Projet

Le projet est organisé de manière modulaire :

```
chapitre2/
├── main.tf              # Configuration de base Terraform
├── iam.tf               # Toutes les ressources IAM
├── s3.tf                # Configuration S3
├── cloudwatch.tf        # Configuration CloudWatch
├── ssm.tf               # Gestion des secrets SSM
├── verify_aws_setup.py  # Script de test Python
├── requirements.txt      # Dépendances Python
├── README.md            # Documentation
└── .gitignore           # Fichiers à ignorer
```

## 🚀 Déploiement

### Prérequis
- Terraform >= 1.0
- AWS CLI configuré
- Python 3 avec boto3

### Étapes de Déploiement

1. **Initialiser Terraform**
   ```bash
   terraform init
   ```

2. **Vérifier le plan**
   ```bash
   terraform plan
   ```

3. **Déployer l'infrastructure**
   ```bash
   terraform apply
   ```

4. **Installer les dépendances Python**
   ```bash
   pip install -r requirements.txt
   ```

5. **Tester l'infrastructure**
   ```bash
   python verify_aws_setup.py
   ```

## 🔍 Explication des Concepts IAM

### Policies vs Roles

**Policies** : Documents JSON qui définissent les permissions
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject"],
      "Resource": "arn:aws:s3:::bucket/*"
    }
  ]
}
```

**Roles** : Identités temporaires avec une Trust Policy
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

### Principe du Moindre Privilège

Dans ce projet, nous appliquons le principe du moindre privilège :
- ✅ S3 : Seulement `GetObject` et `PutObject`
- ✅ CloudWatch : Seulement l'écriture des logs
- ✅ SSM : Seulement `GetParameter` pour le paramètre spécifique

## 🧪 Tests

Le script `verify_aws_setup.py` teste :

1. **Identité AWS** : Vérification des credentials
2. **Paramètre SSM** : Accès à la clé API sécurisée
3. **Bucket S3** : Accès au bucket de stockage
4. **Logs CloudWatch** : Accès au log group

### Exécution des Tests
```bash
python verify_aws_setup.py
```

## 🔒 Sécurité

### Bonnes Pratiques Implémentées
- ✅ Chiffrement AES256 pour S3
- ✅ Versioning activé sur S3
- ✅ Accès public bloqué sur S3
- ✅ Politiques IAM avec principe du moindre privilège
- ✅ Paramètres SSM en SecureString
- ✅ Rétention des logs configurée

## 📚 Ressources d'Apprentissage

### AWS IAM
- [AWS IAM Primer](https://docs.aws.amazon.com/IAM/latest/UserGuide/introduction.html)
- [IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [IAM Policies](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html)

### Terraform
- [Terraform AWS Provider](https://registry.terraform.io/providers/hashicorp/aws/latest/docs)
- [Terraform Best Practices](https://www.terraform.io/docs/cloud/guides/recommended-practices/index.html)

### Boto3
- [Boto3 Documentation](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html)

## 🧹 Nettoyage

Pour supprimer toutes les ressources créées :

```bash
terraform destroy
```

⚠️ **Attention** : Cette commande supprimera définitivement toutes les ressources AWS créées par ce projet.

## 🤝 Support

Pour toute question ou problème :
1. Vérifiez les logs de test : `python verify_aws_setup.py`
2. Consultez la documentation AWS
3. Vérifiez les permissions IAM dans la console AWS

---

**Note** : Ce projet est conçu pour un environnement de développement et d'apprentissage. Pour la production, considérez des configurations de sécurité supplémentaires. 