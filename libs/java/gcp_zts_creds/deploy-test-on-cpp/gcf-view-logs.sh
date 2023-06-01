#!/bin/bash -e
set -o pipefail

cd "$( dirname "$0" )"
. common.sh


time (
  set -x
  gcloud functions logs read "$GCP_FUNCTION_NAME" \
      --region "$GCP_REGION" \
      --limit="${1:-40}"
      # --min-log-level debug
)
