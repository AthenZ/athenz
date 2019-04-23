# setups
```bash
# 1. generate server certificates
sh ./gen-certs.sh

# 2. build docker images
cd ..; make build-docker

# 3. run dockers
make run-docker
```
