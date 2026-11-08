# The temporary OpenBao the copy is opened in, inside the move pod only.
ui = false
storage "raft" {
  path    = "/work/raft"
  node_id = "move-0"
}
listener "tcp" {
  address         = "127.0.0.1:8210"
  cluster_address = "127.0.0.1:8211"
  tls_disable     = 1
  # This copy only: Vault's unseal keys (its recovery keys after the seal moves) mint the temporary token
  # and are replaced by new recovery keys; the cluster's own listeners keep both endpoints off.
  disable_unauthed_generate_root_endpoints = false
  disable_unauthed_rekey_endpoints         = false
}
api_addr     = "http://127.0.0.1:8210"
cluster_addr = "http://127.0.0.1:8211"
# The unseal host's key, as the cluster's members use it (security/openbao.yaml). Token: BAO_TOKEN.
seal "transit" {
  address         = "https://openbao-unseal-host.openbao.svc:8200"
  tls_server_name = "openbao-unseal-host"
  tls_ca_cert     = "/etc/unseal-host/ca.pem"
  mount_path      = "transit/"
  key_name        = "autounseal"
}
