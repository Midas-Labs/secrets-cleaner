# Low-cost self-hosted profile

This profile is for development, demonstrations, and inexpensive single-host
installations. It self-hosts PostgreSQL, Temporal, AutoMQ, RustFS, OpenBao, and
OpenTelemetry. It is intentionally **not** advertised as highly available: one
host, disk, or Docker failure can stop the entire stack.

Only Temporal UI is published, and it binds to `127.0.0.1:8233`. Stateful
services remain on an internal Docker network. The AutoMQ/RustFS wiring follows
the upstream integration pattern, with required generated credentials instead
of demonstration defaults.

## Configure

```bash
cd deploy/compose
cp .env.example .env
chmod 600 .env

# Put each generated value into the matching .env field.
openssl rand -base64 32                 # POSTGRES_PASSWORD
openssl rand -hex 16                    # RUSTFS_ACCESS_KEY
openssl rand -base64 32                 # RUSTFS_SECRET_KEY
docker run --rm automqinc/automq:1.6.0 \
  /opt/automq/kafka/bin/kafka-storage.sh random-uuid  # AUTOMQ_CLUSTER_ID
```

Validate before pulling or starting anything:

```bash
docker compose config --quiet
```

Start the data services:

```bash
docker compose up -d
docker compose ps
```

Initialize and unseal OpenBao from a trusted local shell, store its recovery
shares offline, and never commit them. The single-host profile uses plaintext
transport only inside Docker's `internal` network; customer payloads remain
end-to-end encrypted by the agent protocol. The three-node production profile
must additionally use mTLS between every service.

## Verify AutoMQ/RustFS

```bash
docker compose exec automq bash -ec '
  /opt/automq/kafka/bin/kafka-topics.sh \
    --create --if-not-exists --topic secretsweep-smoke \
    --bootstrap-server automq:9092 --partitions 1 --replication-factor 1
  printf "probe\n" | /opt/automq/kafka/bin/kafka-console-producer.sh \
    --bootstrap-server automq:9092 --topic secretsweep-smoke
  /opt/automq/kafka/bin/kafka-console-consumer.sh \
    --bootstrap-server automq:9092 --topic secretsweep-smoke \
    --from-beginning --max-messages 1 --timeout-ms 10000
'
```

For production, do not put backups on these same volumes. Use an encrypted
off-host destination and test restoration before accepting customer work.
