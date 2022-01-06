#!/usr/bin/env bash

if test -e /etc/pki/tls/certs/ca-bundle.crt; then
  BASE_DIR=$(git rev-parse --show-toplevel)
  mkdir -p "${BASE_DIR}/docker/zts/conf/awscas"
  cd "${BASE_DIR}/docker/zts/conf/awscas" || true
  csplit --elide-empty-files --suffix-format="%02d.pem" -s --prefix parts /etc/pki/tls/certs/ca-bundle.crt '/# Amazon Root CA/' '{3}'
  csplit --elide-empty-files --suffix-format="%02d.pem" -s --prefix bar parts04.pem '/END CERTIFICATE/+1' '{0}'
  rm -f parts00.pem bar01.pem parts04.pem
  sed -i '$d' parts01.pem parts02.pem parts03.pem
  sed -i '1d' parts01.pem parts02.pem parts03.pem bar00.pem
  mv parts01.pem amazon1.pem
  mv parts02.pem amazon2.pem
  mv parts03.pem amazon3.pem
  mv bar00.pem amazon4.pem
else
  echo "not running in aws environment"
fi