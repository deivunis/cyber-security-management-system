#!/usr/bin/env bash
set -euo pipefail

DB_NAME="${DB_NAME:-security_core}"
DB_USER="${DB_USER:-postgres}"

echo "Starting VACUUM FULL on device_observations..."
sudo -u "$DB_USER" psql -d "$DB_NAME" -c "VACUUM FULL ANALYZE device_observations;"
echo "VACUUM FULL completed."
