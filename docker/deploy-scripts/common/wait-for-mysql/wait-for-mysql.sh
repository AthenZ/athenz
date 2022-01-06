#!/usr/bin/env bash

set -e

until mysqladmin ping --silent "$@"; do
  echo 'MySQL is unavailable - will sleep 3s...'
  sleep 3
done

echo 'MySQL is up!'
