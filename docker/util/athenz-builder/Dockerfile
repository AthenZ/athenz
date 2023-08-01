FROM athenz/athenz-mvn-base AS mvn
# date -u +'%Y-%m-%dT%H:%M:%SZ'
ARG BUILD_DATE
# git rev-parse --short HEAD
ARG VCS_REF 

ENV SCREWDRIVER true

LABEL org.label-schema.schema-version="1.0"
LABEL org.label-schema.build-date=$BUILD_DATE
LABEL org.label-schema.name="athenz-builder"
LABEL org.label-schema.description="base image for building Athenz servers"
LABEL org.label-schema.url="https://www.athenz.io/"
LABEL org.label-schema.vcs-url="https://github.com/AthenZ/athenz"
LABEL org.label-schema.vcs-ref=$VCS_REF

WORKDIR /athenz
COPY . .

RUN mvn -B install -pl core/zms -pl core/zts -pl core/msd -pl libs/java/auth_core -pl libs/java/client_common -pl libs/java/server_common -pl libs/java/syncer_common -pl libs/java/dynamodb_client_factory -pl libs/java/instance_provider -pl libs/java/cert_refresher -pl clients/java/zms -pl servers/zms -pl clients/java/zts -pl servers/zts -pl containers/jetty -pl assembly/zms -pl assembly/zts -DskipTests -Djacoco.skip=true -DdockerBuild=true

RUN mkdir -p /tmp/zms \
    && mkdir -p /tmp/zts \
    && mkdir -p /opt/athenz/zms \
    && mkdir -p /opt/athenz/zts

RUN tar xvzf ./assembly/zms/target/athenz-zms*-bin.tar.gz -C /tmp/zms \
    && mv /tmp/zms/athenz-zms-*/* /tmp/zms/ \
    && mv /tmp/zms/etc /opt/athenz/zms/etc \
    && mv /tmp/zms/conf /opt/athenz/zms/conf \
    && mv /tmp/zms/lib /opt/athenz/zms/lib \
    && mv /tmp/zms/webapps /opt/athenz/zms/webapps

RUN tar xvzf ./assembly/zts/target/athenz-zts*-bin.tar.gz -C /tmp/zts \
    && mv /tmp/zts/athenz-zts-*/* /tmp/zts/ \
    && mv /tmp/zts/etc /opt/athenz/zts/etc \
    && mv /tmp/zts/conf /opt/athenz/zts/conf \
    && mv /tmp/zts/lib /opt/athenz/zts/lib \
    && mv /tmp/zts/webapps /opt/athenz/zts/webapps

WORKDIR /opt/athenz

RUN rm -rf /athenz \
    && rm -rf /tmp/zms \
    && rm -rf /tmp/zts
