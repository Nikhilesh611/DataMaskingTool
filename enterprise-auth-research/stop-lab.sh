#!/bin/bash
# Stop the lab
cd "$(dirname "$0")"
echo "Stopping lab infrastructure..."
docker compose down
echo "Lab stopped."
