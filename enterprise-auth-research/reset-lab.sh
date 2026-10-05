#!/bin/bash
# Reset the lab — destroy all data and start fresh
cd "$(dirname "$0")"
echo "Destroying lab infrastructure and all data..."
docker compose down -v
echo "Lab reset complete. Run ./run-lab.sh to start fresh."
