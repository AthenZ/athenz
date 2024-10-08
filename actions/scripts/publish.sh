#!/usr/bin/env bash

MODULE_TYPE=$1

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
      until mvn -B deploy -P ossrh -Dmaven.test.skip=true --projects $1
      do
        [[ counter -eq $max_retry ]] && echo "Failed to deploy package $1" && exit 1
        counter=$(( $counter + 1 ))
        sleep 30
        echo "Re-trying to publish package (attempt #$counter)"
      done
    fi
}

if [[ "$MODULE_TYPE" = "client" ]];
then
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
  deployProject "com.yahoo.athenz:athenz-gcp-zts-creds"
else
  mvn -B --projects core/zms -Dmaven.test.skip=true install
  mvn -B --projects core/zts -Dmaven.test.skip=true install
  mvn -B --projects libs/java/auth_core -Dmaven.test.skip=true install
  mvn -B --projects libs/java/client_common -Dmaven.test.skip=true install
  mvn -B --projects libs/java/cert_refresher -Dmaven.test.skip=true install
  mvn -B --projects clients/java/zms -Dmaven.test.skip=true install
  mvn -B --projects clients/java/zts -Dmaven.test.skip=true install
  deployProject "com.yahoo.athenz:athenz-server-common"
  deployProject "com.yahoo.athenz:athenz-server-k8s-common"
  deployProject "com.yahoo.athenz:athenz-server-aws-common"
  deployProject "com.yahoo.athenz:athenz-instance-provider"
  deployProject "com.yahoo.athenz:athenz-syncer-common"
fi
