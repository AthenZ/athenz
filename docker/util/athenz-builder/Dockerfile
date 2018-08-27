FROM rdl-athenz-server AS rdl

FROM openjdk:8-jdk-alpine

RUN apk add --no-cache curl tar bash procps tree

ARG MAVEN_VERSION=3.5.4
ARG USER_HOME_DIR="/root"
ARG SHA=ce50b1c91364cb77efe3776f756a6d92b76d9038b0a0782f7d53acf1e997a14d
ARG BASE_URL=https://apache.osuosl.org/maven/maven-3/${MAVEN_VERSION}/binaries

RUN mkdir -p /usr/share/maven /usr/share/maven/ref \
  && curl -fsSL -o /tmp/apache-maven.tar.gz ${BASE_URL}/apache-maven-${MAVEN_VERSION}-bin.tar.gz \
  && echo "${SHA}  /tmp/apache-maven.tar.gz" | sha256sum -c - \
  && tar -xzf /tmp/apache-maven.tar.gz -C /usr/share/maven --strip-components=1 \
  && rm -f /tmp/apache-maven.tar.gz \
  && ln -s /usr/share/maven/bin/mvn /usr/bin/mvn

ENV MAVEN_HOME /usr/share/maven
ENV MAVEN_CONFIG "$USER_HOME_DIR/.m2"

COPY --from=rdl /usr/bin/rdl /usr/bin/rdl
COPY --from=rdl /usr/bin/rdl-gen-athenz-server /usr/bin/rdl-gen-athenz-server

WORKDIR /athenz/zms
COPY . .

RUN mvn install -pl core/zms -pl core/zts -pl libs/java/auth_core -pl libs/java/client_common -pl libs/java/server_common -pl libs/java/instance_provider -pl libs/java/cert_refresher -pl clients/java/zms -pl servers/zms -pl servers/zts -pl containers/jetty -pl assembly/zms -pl assembly/zts -Dmaven.test.skip=true

RUN mkdir -p /tmp/zms \
    && tar xvzf ./assembly/zms/target/athenz-zms*-bin.tar.gz -C /tmp/zms \
    && mv /tmp/zms/athenz-zms-*-SNAPSHOT/* /tmp/zms/ \
    && rm -rf /tmp/zms/athenz-zms-*-SNAPSHOT \
    && mkdir -p /opt/athenz/zms \
    && mv /tmp/zms/etc /opt/athenz/zms/etc \
    && mv /tmp/zms/conf /opt/athenz/zms/conf \
    && mv /tmp/zms/lib /opt/athenz/zms/lib \
    && mv /tmp/zms/webapps /opt/athenz/zms/webapps

RUN mkdir -p /tmp/zts \
    && tar xvzf ./assembly/zts/target/athenz-zts*-bin.tar.gz -C /tmp/zts \
    && mv /tmp/zts/athenz-zts-*-SNAPSHOT/* /tmp/zts/ \
    && rm -rf /tmp/zts/athenz-zts-*-SNAPSHOT \
    && mkdir -p /opt/athenz/zts \
    && mv /tmp/zts/etc /opt/athenz/zts/etc \
    && mv /tmp/zts/conf /opt/athenz/zts/conf \
    && mv /tmp/zts/lib /opt/athenz/zts/lib \
    && mv /tmp/zts/webapps /opt/athenz/zts/webapps

WORKDIR /opt/athenz

RUN tree -L 5
