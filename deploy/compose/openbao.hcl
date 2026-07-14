ui = false
disable_mlock = false

storage "raft" {
  path    = "/openbao/data"
  node_id = "compose-1"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true
}

api_addr     = "http://openbao:8200"
cluster_addr = "http://openbao:8201"
