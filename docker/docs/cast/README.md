
<a id="markdown-athenz-demo-recording" name="athenz-demo-recording"></a>
# Athenz Demo Recording

<!-- TOC -->

- [Athenz Demo Recording](#athenz-demo-recording)
  - [Athenz Demo](#athenz-demo)
    - [playback](#playback)
      - [web](#web)
      - [docker](#docker)
    - [recording](#recording)
  - [About asciinema](#about-asciinema)

<!-- /TOC -->

<a id="markdown-athenz-demo" name="athenz-demo"></a>
## Athenz Demo

<a id="markdown-playback" name="playback"></a>
### playback

<a id="markdown-web" name="web"></a>
#### web
- [Athenz Bootstrap Demo](https://asciinema.org/a/330037)
- [Athenz Acceptance Test Demo](https://asciinema.org/a/330038)

<a id="markdown-docker" name="docker"></a>
#### docker

```bash
BASE_DIR="$(git rev-parse --show-toplevel)"
CAST_DIR="${BASE_DIR}/docker/docs/cast"

docker run --rm -ti \
  -v "$HOME/.config/asciinema":/root/.config/asciinema \
  -v "${CAST_DIR}":/root/cast \
  asciinema/asciinema \
  asciinema play --speed=99 /root/cast/athenz-docker-build-demo.cast

docker run --rm -ti \
  -v "$HOME/.config/asciinema":/root/.config/asciinema \
  -v "${CAST_DIR}":/root/cast \
  asciinema/asciinema \
  asciinema play --speed=3 /root/cast/athenz-bootstrap-demo.cast

docker run --rm -ti \
  -v "$HOME/.config/asciinema":/root/.config/asciinema \
  -v "${CAST_DIR}":/root/cast \
  asciinema/asciinema \
  asciinema play --speed=3 /root/cast/athenz-acceptance-test-demo.cast
```

<a id="markdown-recording" name="recording"></a>
### recording

```bash
BASE_DIR="$(git rev-parse --show-toplevel)"
CAST_DIR="${BASE_DIR}/docker/docs/cast"

asciinema rec --overwrite --title='Athenz Docker Build Demo' "${CAST_DIR}/athenz-docker-build-demo.cast"
# cd "$(git rev-parse --show-toplevel)/docker";
# make build;
# exit;

asciinema rec --overwrite --title='Athenz Bootstrap Demo' "${CAST_DIR}/athenz-bootstrap-demo.cast"
# cd "$(git rev-parse --show-toplevel)/docker";
# sh ./docs/cast/bootstrap-demo-welcome-script.sh;
# make deploy-dev;
# echo 'This is the end of this demo. Bye~';
# exit;

asciinema rec --overwrite --title='Athenz Acceptance Test Demo' "${CAST_DIR}/athenz-acceptance-test-demo.cast"
# docker run --rm -it \
#     --network="${DOCKER_NETWORK}" \
#     -v "${BASE_DIR}:/athenz" \
#     --user "$(id -u):$(id -g)" \
#     athenz-setup-env \
#     sh /athenz/docker/deploy-scripts/acceptance-test.sh;
# exit;
```

<a id="markdown-about-asciinema" name="about-asciinema"></a>
## About asciinema
- [Installation - asciinema](https://asciinema.org/docs/installation)
- [Usage - asciinema](https://asciinema.org/docs/usage)
- Installation note
    ```bash
    cd $HOME
    git clone https://github.com/asciinema/asciinema.git
    ```
    ```bash
    export PYTHONPATH="${PYTHONPATH:-}:$HOME/asciinema"
    alias asciinema='python3 -m asciinema'
    ```
- upload note
    ```bash
    asciinema auth

    BASE_DIR="$(git rev-parse --show-toplevel)"
    CAST_DIR="${BASE_DIR}/docker/docs/cast"

    # asciinema upload "${CAST_DIR}/athenz-docker-build-demo.cast"
    asciinema upload "${CAST_DIR}/athenz-bootstrap-demo.cast"
    asciinema upload "${CAST_DIR}/athenz-acceptance-test-demo.cast"
    ```
- upload large file to git: [Git Large File Storage](https://git-lfs.github.com/)
    - [can not upload new objects to public fork  · Issue #1906 · git-lfs/git-lfs](https://github.com/git-lfs/git-lfs/issues/1906)
