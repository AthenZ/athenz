# Setup Docker
-----------------

* [Requirements](#requirements)
    * [Docker](#docker)
* [Launch instance](#launch-instance)
* [Start/Stop Athenz](#startstop-athenz)

## Requirements
---------------

### Docker
-----------

Please checkout https://docs.docker.com/engine/installation/ for docker installation.

## Launch instance
-------------------

Once docker is successfully installed, launch Athenz by executing the following docker command:

```shell
$ docker run -itd -P athenz/athenz
```

The docker container includes all three Athenz Services - ZMS, ZTS and UI. Internally
they're running on the following ports:

| Service | Port |
|---------|------|
|   ZMS   | 4443 |
|   ZTS   | 8443 |
|   UI    | 9443 |

To access these services, first determine the corresponding ports exposed by docker.
Run the following commands to extract the container id assigned to the `athenz/athenz`
image and then use extracted container id as the value for the CONTAINER_ID parameter
in the second command to inspect the ports exposed by docker:

```shell
$ docker ps --filter "ancestor=athenz/athenz" -q
$ docker inspect --format '{{json .NetworkSettings.Ports}}' CONTAINER_ID
```

The output from the inspect command would be similar to:

`{"4443/tcp":[{"HostIp":"0.0.0.0","HostPort":"32776"}],"8443/tcp":[{"HostIp":"0.0.0.0","HostPort":"32775"}],"9443/tcp":[{"HostIp":"0.0.0.0","HostPort":"32774"}]}`

In this setup UI port 9443 is exposed on port 32774. So to access Athenz UI from
the same box, open the web browser with url https://localhost:32774. Since the
services are running with self-signed certificates, configure your browser to
ignore the warnings regarding the UI server certificate.

The container is configured with the following default user details:

 |  User  | Password |
 |--------|----------|
 | athenz |  athenz  |


## Start/Stop Athenz
-----------------------

Run `docker ps` to get the CONTAINER_ID first and then use the extracted
container id with docker stop command:

```shell
$ docker ps --filter "ancestor=athenz/athenz" -q
$ docker stop CONTAINER_ID
```

To start Athenz, execute the following command (replace CONTAINER_ID with
the extract id from the docker ps command):

```shell
$ docker start CONTAINER_ID
```
