#!/usr/bin/env bash

function deployProject ()
{
    max_retry=3
    counter=0
    echo "Publishing package $1..."

    # before publishing we need to make sure that the package
    # is not being asked to be skipped since it was already
    # published in a previous build

    if [[ $PUBLISH_SKIP_PACKAGES == *"$1"* ]]
    then
      echo "Package $1 already published. Skipping..."
    else
      until mvn -B deploy -P ossrh -Dmaven.test.skip=true --projects $1 --settings screwdriver/settings/settings-publish.xml
      do
        [[ counter -eq $max_retry ]] && echo "Failed to deploy package $1" && exit 1
        counter=$(( $counter + 1 ))
        sleep 30
        echo "Re-trying to publish package (attempt #$counter)"
      done
    fi
}

# for openssl 1.1+ we need to add -pbkdf2 to remove the
# warning but that option does not exist in openssl 1.0.x

export GPG_TTY=$(tty)

mkdir screwdriver/deploy
chmod 0400 screwdriver/deploy

openssl aes-256-cbc -pass pass:$GPG_ENCPHRASE -in screwdriver/pubring.gpg.enc -out screwdriver/deploy/pubring.gpg -pbkdf2 -d
openssl aes-256-cbc -pass pass:$GPG_ENCPHRASE -in screwdriver/secring.gpg.enc -out screwdriver/deploy/secring.gpg -pbkdf2 -d

deployProject "com.yahoo.athenz:athenz"
deployProject "com.yahoo.athenz:athenz-zms-core"
deployProject "com.yahoo.athenz:athenz-zts-core"
deployProject "com.yahoo.athenz:athenz-msd-core"
deployProject "com.yahoo.athenz:athenz-auth-core"
deployProject "com.yahoo.athenz:athenz-client-common"
deployProject "com.yahoo.athenz:athenz-cert-refresher"
deployProject "com.yahoo.athenz:athenz-zms-java-client"
deployProject "com.yahoo.athenz:athenz-zts-java-client"
deployProject "com.yahoo.athenz:athenz-zpe-java-client"
deployProject "com.yahoo.athenz:athenz-msd-java-client"
deployProject "com.yahoo.athenz:athenz-server-common"
deployProject "com.yahoo.athenz:athenz-instance-provider"
deployProject "com.yahoo.athenz:athenz-syncer-common"
deployProject "com.yahoo.athenz:athenz-gcp-zts-creds"

rm -rf screwdriver/deploy
