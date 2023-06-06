#!/bin/bash -e
set -o pipefail

cd "$( dirname "$0" )"
. common-wrapper.sh

time { echo ; ( set -x ; curl "https://$GCP_REGION-$GCP_PROJECT_ID.cloudfunctions.net/$GCP_FUNCTION_NAME" ) ; echo ; }
