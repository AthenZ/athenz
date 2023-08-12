# athenz mvn base

FROM athenz/rdl-athenz-server AS rdl

FROM athenz/rdl-athenz-java-model AS rdl-java-model

FROM athenz/rdl-athenz-go-model AS rdl-go-model

FROM athenz/rdl-athenz-java-client AS rdl-java-client

FROM maven:3-eclipse-temurin-11-focal AS mvn
# date -u +'%Y-%m-%dT%H:%M:%SZ'
ARG BUILD_DATE
# git rev-parse --short HEAD
ARG VCS_REF

LABEL org.label-schema.schema-version="1.0"
LABEL org.label-schema.build-date=$BUILD_DATE
LABEL org.label-schema.name="athenz-mvn-base"
LABEL org.label-schema.description="base image for maven cache"
LABEL org.label-schema.url="https://www.athenz.io/"
LABEL org.label-schema.vcs-url="https://github.com/AthenZ/athenz"
LABEL org.label-schema.vcs-ref=$VCS_REF

ARG USER_HOME_DIR="/root"
ENV MAVEN_CONFIG "$USER_HOME_DIR/.m2"

COPY --from=rdl /usr/bin/rdl /usr/bin/rdl
COPY --from=rdl /usr/bin/rdl-gen-athenz-server /usr/bin/rdl-gen-athenz-server
COPY --from=rdl-java-model /usr/bin/rdl-gen-athenz-java-model /usr/bin/rdl-gen-athenz-java-model
COPY --from=rdl-java-client /usr/bin/rdl-gen-athenz-java-client /usr/bin/rdl-gen-athenz-java-client
COPY --from=rdl-go-model /usr/bin/rdl-gen-athenz-go-model /usr/bin/rdl-gen-athenz-go-model

# copy pom.xml
WORKDIR /athenz
COPY pom.xml .
# cat pom.xml | grep "<module>.*</module>" | awk -F'[><]' '{ printf "COPY ./%s/pom.xml ./%s/pom.xml\n", $3, $3 }'
COPY ./rdl/rdl-gen-athenz-server/pom.xml ./rdl/rdl-gen-athenz-server/pom.xml
COPY ./rdl/rdl-gen-athenz-go-model/pom.xml ./rdl/rdl-gen-athenz-go-model/pom.xml
COPY ./rdl/rdl-gen-athenz-go-client/pom.xml ./rdl/rdl-gen-athenz-go-client/pom.xml
COPY ./rdl/rdl-gen-athenz-java-model/pom.xml ./rdl/rdl-gen-athenz-java-model/pom.xml
COPY ./rdl/rdl-gen-athenz-java-client/pom.xml ./rdl/rdl-gen-athenz-java-client/pom.xml
COPY ./core/zms/pom.xml ./core/zms/pom.xml
COPY ./core/zts/pom.xml ./core/zts/pom.xml
COPY ./libs/java/auth_core/pom.xml ./libs/java/auth_core/pom.xml
COPY ./libs/java/client_common/pom.xml ./libs/java/client_common/pom.xml
COPY ./libs/java/server_common/pom.xml ./libs/java/server_common/pom.xml
COPY ./libs/java/syncer_common/pom.xml ./libs/java/syncer_common/pom.xml
COPY ./libs/java/dynamodb_client_factory/pom.xml ./libs/java/dynamodb_client_factory/pom.xml
COPY ./libs/java/instance_provider/pom.xml ./libs/java/instance_provider/pom.xml
COPY ./libs/java/cert_refresher/pom.xml ./libs/java/cert_refresher/pom.xml
COPY ./clients/java/zms/pom.xml ./clients/java/zms/pom.xml
COPY ./clients/java/zts/pom.xml ./clients/java/zts/pom.xml
COPY ./clients/java/zpe/pom.xml ./clients/java/zpe/pom.xml
COPY ./servers/zms/pom.xml ./servers/zms/pom.xml
COPY ./servers/zts/pom.xml ./servers/zts/pom.xml
COPY ./containers/jetty/pom.xml ./containers/jetty/pom.xml
COPY ./clients/go/zms/pom.xml ./clients/go/zms/pom.xml
COPY ./clients/go/zts/pom.xml ./clients/go/zts/pom.xml
COPY ./libs/go/zmscli/pom.xml ./libs/go/zmscli/pom.xml
COPY ./libs/go/zmssvctoken/pom.xml ./libs/go/zmssvctoken/pom.xml
COPY ./libs/go/athenzutils/pom.xml ./libs/go/athenzutils/pom.xml
COPY ./libs/go/athenzconf/pom.xml ./libs/go/athenzconf/pom.xml
COPY ./utils/zms-cli/pom.xml ./utils/zms-cli/pom.xml
COPY ./utils/athenz-conf/pom.xml ./utils/athenz-conf/pom.xml
COPY ./utils/zms-svctoken/pom.xml ./utils/zms-svctoken/pom.xml
COPY ./utils/zpe-updater/pom.xml ./utils/zpe-updater/pom.xml
COPY ./utils/zts-roletoken/pom.xml ./utils/zts-roletoken/pom.xml
COPY ./utils/zts-accesstoken/pom.xml ./utils/zts-accesstoken/pom.xml
COPY ./utils/zts-rolecert/pom.xml ./utils/zts-rolecert/pom.xml
COPY ./utils/zts-svccert/pom.xml ./utils/zts-svccert/pom.xml
COPY ./libs/nodejs/auth_core/pom.xml ./libs/nodejs/auth_core/pom.xml
COPY ./clients/nodejs/zts/pom.xml ./clients/nodejs/zts/pom.xml
COPY ./clients/nodejs/zpe/pom.xml ./clients/nodejs/zpe/pom.xml
COPY ./ui/pom.xml ./ui/pom.xml
COPY ./assembly/zms/pom.xml ./assembly/zms/pom.xml
COPY ./assembly/zts/pom.xml ./assembly/zts/pom.xml
COPY ./assembly/ui/pom.xml ./assembly/ui/pom.xml
COPY ./assembly/utils/pom.xml ./assembly/utils/pom.xml

# RUN mvn -U -B dependency:resolve --fail-never
# RUN mvn -U -B dependency:resolve --fail-never -DexcludeGroupIds=com.yahoo.athenz

RUN mvn -U -B dependency:go-offline --fail-never -DdockerBuild=true
# RUN mvn -U -B dependency:go-offline --fail-never -DexcludeGroupIds=com.yahoo.athenz

# docker run -it --name athenz-base-mvn athenz-base-mvn sh; docker rm athenz-base-mvn
