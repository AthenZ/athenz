# setups
```bash
# 1. generate server certificates
sh ./gen-certs.sh

# 2. build docker images
cd ..; make build-docker

# 3. run dockers
make run-docker

# 4. add ZTS public key to ZMS
docker run -it --net=host \
  -v `pwd`/docker:/opt/athenz \
  athenz-cli \
  'zms-cli -c /opt/athenz/zms/var/certs/zms_cert.pem -z https://localhost:4443/zms/v1 -d sys.auth add-service zts 0 /opt/athenz/zts/var/keys/zts_public.pem'
```

# pending issues
1. cannot set ZTS public key to ZMS (zms-cli: `Unable to get NToken: Cannot get user token for user:  error: invalid character '<' looking for beginning of value`)
1. docker network setup for DB
