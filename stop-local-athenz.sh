#!/bin/sh

set -eu
set -o pipefail

cd docker

# delete the cert from Mac keychain ( Mac specific optional step )
# security delete-certificate -c "Sample Self Signed Athenz CA" -t

# stop containers and remove generated files, local images
make remove-local

cd ..