FROM rdl-athenz-server AS rdl

FROM athenz-builder AS builder

COPY --from=rdl /usr/bin/rdl /usr/bin/rdl
COPY --from=rdl /usr/bin/rdl-gen-athenz-server /usr/bin/rdl-gen-athenz-server

WORKDIR /athenz/zts
COPY . .

RUN mvn install -pl core/zms -Dmaven.test.skip=true
RUN mvn install -pl core/zts -Dmaven.test.skip=true
RUN mvn install -pl libs/java/auth_core -Dmaven.test.skip=true
RUN mvn install -pl libs/java/client_common -Dmaven.test.skip=true
RUN mvn install -pl libs/java/server_common -Dmaven.test.skip=true
RUN mvn install -pl libs/java/instance_provider -Dmaven.test.skip=true
RUN mvn install -pl libs/java/cert_refresher -Dmaven.test.skip=true
RUN mvn install -pl clients/java/zms -Dmaven.test.skip=true
RUN mvn install -pl servers/zts -Dmaven.test.skip=true
RUN mvn install -pl containers/jetty -Dmaven.test.skip=true

RUN mvn install -pl assembly/zts -Dmaven.test.skip=true

RUN mkdir -p /tmp/zts \
    && tar xvzf ./assembly/zts/target/athenz-zts*-bin.tar.gz -C /tmp/zts \
    && mkdir -p /opt/athenz/zts \
    && mv /tmp/zts/etc /opt/athenz/zts/etc \
    && mv /tmp/zts/conf /opt/athenz/zts/conf \
    && mv /tmp/zts/lib /opt/athenz/zts/lib \
    && mv /tmp/zts/webapp /opt/athenz/zts/webapp

FROM openjdk:8-jre-alpine AS runner

WORKDIR /opt/athenz/zts

COPY --from=builder /opt/athenz/zts/* .

ENTRYPOINT ["java"]
CMD ["-classpath", "lib/jars/*", "-Dathenz.root_dir=.", "-Dathenz.zts.root_dir=.", "-Dathenz.prop_file=conf/zts_server/athenz.properties", "-Dathenz.zts.prop_file=conf/zts_server/zts.properties", "-Dlogback.configurationFile=conf/zts_server/logback.xml", "com.yahoo.athenz.container.AthenzJettyContainer"]
