FROM athenz-mvn-base AS mvn

WORKDIR /athenz
COPY . .

RUN mvn install -pl core/zms -pl core/zts -pl libs/java/auth_core -pl libs/java/client_common -pl libs/java/server_common -pl libs/java/instance_provider -pl libs/java/cert_refresher -pl clients/java/zms -pl servers/zms -pl servers/zts -pl containers/jetty -pl assembly/zms -pl assembly/zts -Dmaven.test.skip=true

RUN mkdir -p /tmp/zms \
    && mkdir -p /tmp/zts \
    && mkdir -p /opt/athenz/zms \
    && mkdir -p /opt/athenz/zts

RUN tar xvzf ./assembly/zms/target/athenz-zms*-bin.tar.gz -C /tmp/zms \
    && mv /tmp/zms/athenz-zms-*-SNAPSHOT/* /tmp/zms/ \
    && mv /tmp/zms/etc /opt/athenz/zms/etc \
    && mv /tmp/zms/conf /opt/athenz/zms/conf \
    && mv /tmp/zms/lib /opt/athenz/zms/lib \
    && mv /tmp/zms/webapps /opt/athenz/zms/webapps

RUN tar xvzf ./assembly/zts/target/athenz-zts*-bin.tar.gz -C /tmp/zts \
    && mv /tmp/zts/athenz-zts-*-SNAPSHOT/* /tmp/zts/ \
    && mv /tmp/zts/etc /opt/athenz/zts/etc \
    && mv /tmp/zts/conf /opt/athenz/zts/conf \
    && mv /tmp/zts/lib /opt/athenz/zts/lib \
    && mv /tmp/zts/webapps /opt/athenz/zts/webapps

WORKDIR /opt/athenz

RUN rm -rf /athenz \
    && rm -rf /tmp/zms \
    && rm -rf /tmp/zts
