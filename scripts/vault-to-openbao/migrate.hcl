# Vault's own file storage, copied into the move pod, to Raft (which OpenBao reads).
storage_source "file" { path = "/work/file" }
storage_destination "raft" {
  path    = "/work/raft"
  node_id = "move-0"
}
cluster_addr = "http://127.0.0.1:8211"
