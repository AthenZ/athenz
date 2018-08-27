FROM athenz-builder AS builder

FROM openjdk:8-jre-alpine

WORKDIR /opt/athenz

COPY --from=builder /opt/athenz/zts .

WORKDIR /opt/athenz/zts

ENTRYPOINT ["java"]
CMD ["-classpath", "lib/jars/*", "-Dathenz.root_dir=.", "-Dathenz.zts.root_dir=.", "-Dathenz.prop_file=conf/zts_server/athenz.properties", "-Dathenz.zts.prop_file=conf/zts_server/zts.properties", "-Dlogback.configurationFile=conf/zts_server/logback.xml", "com.yahoo.athenz.container.AthenzJettyContainer"]
