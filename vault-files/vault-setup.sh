cd "${0%/*}"
export VAULT_ADDR=http://127.0.0.1:8200
docker run \
    --rm \
    --cap-add=IPC_LOCK \
    -e 'VAULT_DEV_ROOT_TOKEN_ID=root' \
    -p 8200:8200/tcp \
    -d \
    --name=dev-vault \
    vault
echo Hold on a second.
sleep 2
vault login root
vault secrets enable transit
vault write -f transit/keys/syslogd type="rsa-4096"
vault policy write syslogd ./syslogd.hcl
curl -s \
    --header "X-Vault-Token: root" \
    --header "Content-Type: application/json" \
    --request POST \
    -d '{"policies": ["default","syslogd"],"metadata": {"user": "syslogd"},"ttl": "720h","renewable": true}' \
    http://127.0.0.1:8200/v1/auth/token/create \
| jq -r '.auth.client_token' \
| ./update-token.py