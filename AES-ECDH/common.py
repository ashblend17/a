# Set variables
RESOURCE_GROUP="lab7-rg"
STORAGE_ACCOUNT="lab7storageaccount$RANDOM"
CONTAINER_NAME="lab7container"
USER1_NAME="lab7user1"
USER2_NAME="lab7user2"
PASSWORD1="StrongP@ssword1!"
PASSWORD2="StrongP@ssword2!"

# 1. Create Resource Group
az group create --name $RESOURCE_GROUP --location eastus

# 2. Create Storage Account
az storage account create \
  --name $STORAGE_ACCOUNT \
  --resource-group $RESOURCE_GROUP \
  --location eastus \
  --sku Standard_LRS \
  --kind StorageV2

# 3. Create Blob Container (private access)
az storage container create \
  --account-name $STORAGE_ACCOUNT \
  --name $CONTAINER_NAME

# 4. Create User1 (Read-Only User)
az ad user create \
  --display-name "Lab7 User1" \
  --user-principal-name "${USER1_NAME}@$(az account show --query user.name -o tsv | cut -d'@' -f2)" \
  --password $PASSWORD1 \
  --force-change-password-next-login false

# 5. Create User2 (Read/Write User)
az ad user create \
  --display-name "Lab7 User2" \
  --user-principal-name "${USER2_NAME}@$(az account show --query user.name -o tsv | cut -d'@' -f2)" \
  --password $PASSWORD2 \
  --force-change-password-next-login false

# 6. Assign Read-Only Role to User1
az role assignment create \
  --assignee "${USER1_NAME}@$(az account show --query user.name -o tsv | cut -d'@' -f2)" \
  --role "Storage Blob Data Reader" \
  --scope $(az storage account show --name $STORAGE_ACCOUNT --resource-group $RESOURCE_GROUP --query id -o tsv)

# 7. Assign Contributor Role to User2
az role assignment create \
  --assignee "${USER2_NAME}@$(az account show --query user.name -o tsv | cut -d'@' -f2)" \
  --role "Storage Blob Data Contributor" \
  --scope $(az storage account show --name $STORAGE_ACCOUNT --resource-group $RESOURCE_GROUP --query id -o tsv)

# 8. Output information
echo "-------------------------"
echo "User 1 (Read-Only Access):"
echo "Username: ${USER1_NAME}@$(az account show --query user.name -o tsv | cut -d'@' -f2)"
echo "Password: $PASSWORD1"
echo ""
echo "User 2 (Read/Write Access):"
echo "Username: ${USER2_NAME}@$(az account show --query user.name -o tsv | cut -d'@' -f2)"
echo "Password: $PASSWORD2"
echo ""
echo "Storage Account: $STORAGE_ACCOUNT"
echo "Container: $CONTAINER_NAME"
echo "-------------------------"
