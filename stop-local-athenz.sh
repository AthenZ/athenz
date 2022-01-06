#!/usr/bin/env bash

set -eu
set -o pipefail

cd docker

# import functions
. ./setup-scripts/common/color-print.sh

# stop containers and remove generated files, local images
make remove-all

cd ..

printf '\n'
printf 'If you are on Mac you can run the following command to remove the self-signed certificate from login keychain. \n' | colored_cat y
printf 'security delete-certificate -c "Sample Self Signed Athenz CA" -t'
printf '\n'
printf 'If you want to clean up docker images please run the following command' | colored_cat y
printf '\n'
printf 'cd docker && make remove-local-images && cd ..'
printf '\n'