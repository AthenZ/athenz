#!/usr/bin/env bash

nameservers=$( grep -v '^#' < /etc/resolv.conf | grep nameserver | awk '{print $2}')
LOCAL_ENV_NS=""
while IFS=$(printf ' \n\t') read -r line; do
  LOCAL_ENV_NS="${LOCAL_ENV_NS:+${LOCAL_ENV_NS} }--dns ${line}"
done <<EOF
$nameservers
EOF
export LOCAL_ENV_NS