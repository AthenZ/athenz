FROM rdl-athenz-server AS rdl

FROM athenz-builder AS builder

COPY --from=rdl /usr/bin/rdl /usr/bin/rdl
COPY --from=rdl /usr/bin/rdl-gen-athenz-server /usr/bin/rdl-gen-athenz-server

WORKDIR /athenz/zms
COPY . .

RUN mvn install -pl core/zms -pl core/zts -pl libs/java/auth_core -pl libs/java/client_common -pl libs/java/server_common -pl libs/java/instance_provider -pl servers/zms -pl containers/jetty -pl assembly/zms -Dmaven.test.skip=true

RUN mkdir -p /tmp/zms \
    && tar xvzf ./assembly/zms/target/athenz-zms*-bin.tar.gz -C /tmp/zms \
    && mkdir -p /opt/athenz/zms \
    && mv /tmp/zms/etc /opt/athenz/zms/etc \
    && mv /tmp/zms/conf /opt/athenz/zms/conf \
    && mv /tmp/zms/lib /opt/athenz/zms/lib \
    && mv /tmp/zms/webapp /opt/athenz/zms/webapp

FROM openjdk:8-jre-alpine AS runner

WORKDIR /opt/athenz/zms

COPY --from=builder /opt/athenz/zms/* .

ENTRYPOINT ["java"]
CMD ["-classpath", "lib/jars/*", "-Dathenz.prop_file=conf/zms_server/athenz.properties", "-Dathenz.zms.prop_file=conf/zms_server/zms.properties", "-Dlogback.configurationFile=conf/zms_server/logback.xml", "com.yahoo.athenz.container.AthenzJettyContainer"]

