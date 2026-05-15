#!/usr/bin/env bash
set -euo pipefail

DB_NAME="${DB_NAME:-security_core}"
DB_USER="${DB_USER:-postgres}"
KEEP_DAYS="${DEVICE_OBSERVATIONS_KEEP_DAYS:-14}"
BATCH_SIZE="${DEVICE_OBSERVATIONS_BATCH_SIZE:-50000}"
MAX_LOOPS="${DEVICE_OBSERVATIONS_MAX_LOOPS:-200}"

loops=0
total_deleted=0

while true; do
  deleted=$(sudo -u "$DB_USER" psql -d "$DB_NAME" -tA -c "SELECT cleanup_device_observations(${KEEP_DAYS}, ${BATCH_SIZE});")
  deleted="${deleted//[[:space:]]/}"
  deleted="${deleted:-0}"
  total_deleted=$((total_deleted + deleted))
  echo "Deleted rows in batch: $deleted"

  if [[ "$deleted" == "0" ]]; then
    break
  fi

  loops=$((loops + 1))
  if [[ "$loops" -ge "$MAX_LOOPS" ]]; then
    echo "Reached max loops (${MAX_LOOPS}), stopping early."
    break
  fi

  sleep 0.2
done

sudo -u "$DB_USER" psql -d "$DB_NAME" -c "VACUUM ANALYZE device_observations;"

echo "Total deleted rows: $total_deleted"
