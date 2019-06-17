#!/bin/sh

set -e

# host="$1"

until mysqladmin ping --silent; do
  >&2 echo "MySQL is unavailable - sleeping..."
  sleep 1
done

>&2 echo "MySQL is up!"
logout
