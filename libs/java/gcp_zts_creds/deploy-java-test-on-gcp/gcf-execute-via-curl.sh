#!/bin/bash -e
set -o pipefail

cd "$( dirname "$0" )"
. common-wrapper.sh

echo
time OUTPUT="$( set -x ; curl "https://$GCP_REGION-$GCP_PROJECT_ID.cloudfunctions.net/$GCP_FUNCTION_NAME" )"
echo "$OUTPUT"
echo

echo "======> Trying to show certificate:"
echo "$OUTPUT" |
grep '"x509Certificate": "-----BEGIN CERTIFICATE-----' |
tail -1 |
sed -e 's/"x509Certificate"://' -e 's/,$//' |
jq -r '.' |
( set -x ; openssl x509 -text -noout ) |
gawk '
    # Replace multi-lined "Modulus:" and "Signature Algorithm:" with a single "..." line.
    {
      current = match($0, /^( *)[0-9a-f][0-9a-f](:[0-9a-f][0-9a-f])*:?$/, m);
      if (!current) {
        print;
      } else if (!last) {
        print m[1] "...";
      }
      last = current;
    }
  '
echo
