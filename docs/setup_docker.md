# Setup Docker
-----------------

* [Requirements](#requirements)
    * [Docker](#docker)
* [Launch instance](#launch-instance)
* [Start/Stop Athenz](#startstop-athenz)

## Requirements
---------------

### Docker
----------

Please checkout https://docs.docker.com/engine/installation/ for docker installation.

## Launch instance
------------------

The docker container includes all three Athenz Services - ZMS, ZTS and UI. Internally
they're running on the following ports:

| Service | Port |
|---------|------|
|   ZMS   | 4443 |
|   ZTS   | 8443 |
|   UI    | 9443 |

and those three ports must be exposed and available on the docker host as well.

Once docker is successfully installed, launch Athenz by executing the following docker command.

```shell
$ docker run -itd -h <server-hostname> -p 9443:9443 -p 4443:4443 -p 8443:8443 -e ZMS_SERVER=<server-hostname> -e UI_SERVER=<server-hostname> athenz/athenz
```

To access Athenz UI, open your browser with url

```
https://<server-hostname>:9443/athenz
```

Since the services are running with self-signed certificates, configure your browser to
ignore the warnings regarding the UI server certificate.

The administrator must first access the ZMS Server endpoint in the browser to
accept the exception since the Athenz UI contacts ZMS Server to get an authorized
token for the user when logging in. The administrator must access:

```
https://<server-hostname>:4443/zms/v1/schema
```

The container is configured with the following default user details:

 |  User  | Password |
 |--------|----------|
 | athenz |  athenz  |


## Start/Stop Athenz
--------------------

Run `docker ps` to get the CONTAINER_ID first and then use the extracted
container id with docker stop command:

```shell
$ docker ps --filter "ancestor=athenz/athenz" -q
$ docker stop CONTAINER_ID
```

To start Athenz, execute the following commands first to determine the stopped
Athenz container id and then start the container with docker start command:

```shell
$ docker container ls -a
$ docker start CONTAINER_ID
```

