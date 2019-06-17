#!/bin/sh

set -e

host="$1"

until mysqladmin ping --host "${host}" --silent; do
  echo "MySQL is unavailable - sleeping..."
  sleep 1
done

echo "MySQL is up!"
