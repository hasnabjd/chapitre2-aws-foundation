# PosHub AWS Infrastructure - Makefile

.PHONY: help init plan deploy test output destroy clean


# Initialiser Terraform
init:
	@echo "🔧 Initialisation de Terraform..."
	terraform init

# Vérifier les changements
plan: 
	@echo "📋 Vérification des changements..."
	terraform plan

# Déployer l'infrastructure
deploy: 
	@echo "🚀 Déploiement de l'infrastructure..."
	terraform apply -auto-approve

# Tester tous les composants
test:
	@echo "🧪 Test de l'infrastructure..."
	poetry run python verify_aws_infra.py

# Afficher les outputs
output:
	@echo "📊 Outputs Terraform:"
	terraform output



# Nettoyer les fichiers temporaires
clean:
	@echo "🧹 Nettoyage des fichiers temporaires..."
	rm -rf .terraform
	rm -f .terraform.lock.hcl
	rm -f terraform.tfstate.backup 