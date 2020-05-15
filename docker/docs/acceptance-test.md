<a id="markdown-acceptance-test" name="acceptance-test"></a>
# Acceptance test

<!-- TOC -->

- [Acceptance test](#acceptance-test)
    - [Prerequisites](#prerequisites)
    - [Test](#test)
    - [Expected Output (cast)](#expected-output-cast)

<!-- /TOC -->

<a id="markdown-prerequisites" name="prerequisites"></a>
## Prerequisites

1. Env. setup done. ([env.sh](../env.sh))
1. Bootstrap setup done. ([Done step 1, 2, 3, 4, 5](./Athenz-bootstrap.md#bootstrap-steps))
1. ZMS is running. ([zms-setup](./zms-setup.md))
1. ZTS is running. ([zts-setup](./zts-setup.md))
1. All the setup commands below are expected to run inside [athenz-setup-env](../setup-scripts/Dockerfile) container.
```bash
docker run --rm -it \
    --network="${DOCKER_NETWORK}" \
    -v "${BASE_DIR}:/athenz" \
    --user "$(id -u):$(id -g)" \
    athenz-setup-env \
    sh
```

<a id="markdown-test" name="test"></a>
## Test

```bash
sh /athenz/docker/deploy-scripts/acceptance-test.sh

# force reset testing data
# sh /athenz/docker/deploy-scripts/acceptance-test-reset.sh
```

<a id="markdown-expected-output-castcast" name="expected-output-castcast"></a>
## Expected Output ([cast](./cast))

[![asciicast](https://asciinema.org/a/330038.svg)](https://asciinema.org/a/330038)
