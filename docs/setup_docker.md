# Setup Docker
-----------------

* [Requirements](#requirements)
    * [docker](#docker)
* [Launch instance](#launch-instance)
* [Start/Stop Athenz](#startstop-athenz)

## Requirements
---------------

### docker
-----------

Please checkout https://docs.docker.com/engine/installation/ for docker installation.


## Launch instance
-------------------

Once you have installed docker, launch Athenz by executing the following docker command:

```shell
docker run -itd -P athenz/athenz
```

Once you have started the docker container, you can access Athenz via ports exposed by docker.

For accessing Athenz UI, open your browser with url https://localhost:32786

Internally, Athenz UI Server will be listening on port 9443.  ZMS will be listening on port 4443 and ZTS will be on port 8443.

default login/password is athenz:athenz

```shell
amountblood-lm:athenz charlesk$ docker ps
CONTAINER ID        IMAGE                  COMMAND                  CREATED             STATUS              PORTS                                                                       NAMES
6cc857e7f97e        athenz/athenz   "/bin/sh -c '/opt/..."   6 minutes ago       Up 2 seconds        0.0.0.0:32788->4443/tcp, 0.0.0.0:32787->8443/tcp, 0.0.0.0:32786->9443/tcp   elegant_wozniak
```


## Start/Stop Athenz
-----------------------

run 'docker ps' to get the CONTAINER ID first.

```shell
amountblood-lm:athenz charlesk$ docker stop 6cc857e7f97e
```

To start Athenz, execute the following commands:

```shell
amountblood-lm:athenz charlesk$ docker start 6cc857e7f97e
```

