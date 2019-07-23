#!/bin/sh

set -e

host="$1"

until mysqladmin ping --host "${host}" --silent; do
  echo 'MySQL is unavailable - will sleep 3s...'
  sleep 3
done

echo 'MySQL is up!'
