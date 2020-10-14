FROM athenz-mvn-base AS mvn
# date -u +'%Y-%m-%dT%H:%M:%SZ'
ARG BUILD_DATE
# git rev-parse --short HEAD
ARG VCS_REF

LABEL org.label-schema.schema-version="1.0"
LABEL org.label-schema.build-date=$BUILD_DATE
LABEL org.label-schema.name="athenz-cli-util"
LABEL org.label-schema.description="All in one image containing all Athenz CLI utilities"
LABEL org.label-schema.url="https://www.athenz.io/"
LABEL org.label-schema.vcs-url="https://github.com/yahoo/athenz"
LABEL org.label-schema.vcs-ref=$VCS_REF
# LABEL maintainer "YJ Athenz Team <>"


# install go
RUN apk add --no-cache --virtual .build-deps gcc musl-dev openssl make go git
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
  mvn install -Dmaven.test.skip=true -Djacoco.skip=true \
  -pl core/zms \
  -pl core/zts \
  -pl libs/java/auth_core \
  -pl libs/java/client_common \
  -pl libs/java/cert_refresher \
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
