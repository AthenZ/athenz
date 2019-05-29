FROM rdl-athenz-server AS rdl

FROM openjdk:8-jdk-alpine

RUN apk add --no-cache curl tar bash procps make

ARG MAVEN_VERSION=3.5.4
ARG MAVEN_BIN_URL=https://apache.osuosl.org/maven/maven-3/${MAVEN_VERSION}/binaries
ARG MAVEN_BIN_SHA=ce50b1c91364cb77efe3776f756a6d92b76d9038b0a0782f7d53acf1e997a14d
ARG USER_HOME_DIR="/root"

RUN mkdir -p /usr/share/maven /usr/share/maven/ref \
  && curl -fsSL -o /tmp/apache-maven.tar.gz ${MAVEN_BIN_URL}/apache-maven-${MAVEN_VERSION}-bin.tar.gz \
  && echo "${MAVEN_BIN_SHA}  /tmp/apache-maven.tar.gz" | sha256sum -c - \
  && tar -xzf /tmp/apache-maven.tar.gz -C /usr/share/maven --strip-components=1 \
  && rm -f /tmp/apache-maven.tar.gz \
  && ln -s /usr/share/maven/bin/mvn /usr/bin/mvn

ENV MAVEN_HOME /usr/share/maven
ENV MAVEN_CONFIG "$USER_HOME_DIR/.m2"

COPY --from=rdl /usr/bin/rdl /usr/bin/rdl
COPY --from=rdl /usr/bin/rdl-gen-athenz-server /usr/bin/rdl-gen-athenz-server

# install go
RUN apk add --no-cache --virtual .build-deps gcc musl-dev openssl go git
ENV GOPATH="/root/go"
WORKDIR ${GOPATH}/src/github.com/yahoo/athenz
COPY . .

# cache maven dependency
# RUN mvn dependency:go-offline -DexcludeGroupIds="com.yahoo.athenz"

RUN mkdir -p "${GOPATH}/bin"
ENV PATH="${GOPATH}/bin:${PATH}"
RUN GO111MODULE=on \
  CGO_ENABLED=0 \
  CGO_CXXFLAGS="-g -Ofast -march=native" \
  CGO_FFLAGS="-g -Ofast -march=native" \
  CGO_LDFLAGS="-g -Ofast -march=native" \
  GOOS=$(go env GOOS) \
  GOARCH=$(go env GOARCH) \
  mvn install -Dmaven.test.skip=true \
  -pl core/zms \
  -pl core/zts \
  -pl libs/java/auth_core \
  -pl libs/java/client_common \
  -pl clients/java/zts/core \
  -pl clients/java/zts/shade \
  # go projects
  -pl rdl/rdl-gen-athenz-go-client \
  -pl clients/go/zms \
  -pl clients/go/zts \
  -pl libs/go/zmscli \
  -pl libs/go/zmssvctoken \
  -pl libs/go/athenzutils \
  -pl libs/go/athenzconf \
  -pl utils/zms-cli \
  -pl utils/athenz-conf \
  -pl utils/zms-svctoken \
  -pl utils/zpe_policy_updater \
  -pl utils/zpe-updater \
  -pl utils/zts-roletoken \
  -pl utils/zts-accesstoken \
  -pl utils/zts-rolecert \
  -pl utils/zts-svccert \
  -pl assembly/utils

# RUN mkdir -p /tmp/zms \
#   && mkdir -p /tmp/zts \
#   && mkdir -p /opt/athenz/zms \
#   && mkdir -p /opt/athenz/zts

# RUN tar xvzf ./assembly/zms/target/athenz-zms*-bin.tar.gz -C /tmp/zms \
#   && mv /tmp/zms/athenz-zms-*-SNAPSHOT/* /tmp/zms/ \
#   && mv /tmp/zms/etc /opt/athenz/zms/etc \
#   && mv /tmp/zms/conf /opt/athenz/zms/conf \
#   && mv /tmp/zms/lib /opt/athenz/zms/lib \
#   && mv /tmp/zms/webapps /opt/athenz/zms/webapps

# RUN tar xvzf ./assembly/zts/target/athenz-zts*-bin.tar.gz -C /tmp/zts \
#   && mv /tmp/zts/athenz-zts-*-SNAPSHOT/* /tmp/zts/ \
#   && mv /tmp/zts/etc /opt/athenz/zts/etc \
#   && mv /tmp/zts/conf /opt/athenz/zts/conf \
#   && mv /tmp/zts/lib /opt/athenz/zts/lib \
#   && mv /tmp/zts/webapps /opt/athenz/zts/webapps

# WORKDIR /opt/athenz

# RUN rm -rf /athenz \
#   && rm -rf /tmp/zms \
#   && rm -rf /tmp/zts
