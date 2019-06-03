# setups

[setup-dev.md](./docs/setup-dev.md)

## useful commands

```bash
docker stack ps athenz
less ./docker/logs/zms/server.log
less ./docker/logs/zts/server.log

sudo systemctl restart docker

# check connectivity
apk add curl
curl localhost:4443/zms/v1 -o -
curl localhost:3306 -o -
telnet localhost 4443

# mysql
mysql -v -u root --password=mariadb --host=127.0.0.1 --port=3306
mysql -v -u root --password=mariadb --host=127.0.0.1 --port=3307
```
## TO-DO

-   UI
    1.  convert `default-config.js` parameters to ENV
    1.  configurable listering port
-   athenz-cli
    -   build with separated docker files
-   common
    -   split setup script for different component
