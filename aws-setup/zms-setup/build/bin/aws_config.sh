#!/bin/bash

aws_config_dir="$HOME/.aws"

if [ -z "$HOME" ]; then
    aws_config_dir="/athenz-zms/.aws"
fi

echo "Configuring aws config in $aws_config_dir"

if [ ! -d "$aws_config_dir" ]; then
        mkdir $aws_config_dir
fi

aws_config="[default]\nregion=$REGION"
echo -e $aws_config > $aws_config_dir/config

aws configure set s3.signature_version s3v4
