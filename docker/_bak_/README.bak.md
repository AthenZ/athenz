### UI Section (backup)

```bash
# 4.1 (optional) if you are running web browser and docker containers in the same host
export HOSTNAME=localhost
# 4.2. run Athenz
make run-docker-dev
```
- Note for UI
    - To ignore certificate warning from the browser,
        1. for ZMS server certificate,
            1. get ZMS URL by `echo https://${HOSTNAME}:${ZMS_PORT:-4443}/zms/v1/status`
            1. access ZMS using above URL in the browser
            1. ignore the browser warning (certificate authority invalid)
        1. for UI server certificate,
            1. get UI URL by `echo https://${HOSTNAME}:${UI_PORT:-443}/`
            1. access UI using above URL in the browser
            1. ignore the browser warning (certificate authority invalid)
        - Why do I need to explicitly ignore certificate warning from the browser for both ZMS and UI?
            - You need to connect to ZMS to get a user token during the login process of UI.
            - Since the certificates generated in DEV. deployment are all self-signed certificates, they are not trusted by the browser.
            - Also, they may not have the correct `${HOSTNAME}` in the SAN field depending on your DEV. deployment.
            - Hence, explicitly ignoring the browsers warning message is needed for both ZMS and UI.
    - UI login username/password
        - username: `admin` ([zms.properties](./zms/conf/zms.properties#L37-L41))
        - password: `replace_me_with_a_strong_password` ([deploy script](./deploy-scripts/1.2.config-zms-domain-admin.dev.sh#L12))
