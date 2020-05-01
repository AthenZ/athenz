# concerns

1. [discuss] nginx TCP proxy (external IPs) / TLS passthrough
    1. ZMS certificate CN
        1. `echo "curl: (51) SSL: no alternative certificate subject name matches target host name 'kmaster.wfan'`
    1. related configs
        1. [TLS/HTTPS - NGINX Ingress Controller](https://kubernetes.github.io/ingress-nginx/user-guide/tls/#ssl-passthrough)
        1. NodePort: [kubernetes/ingress-nginx](https://github.com/kubernetes/ingress-nginx/blob/c8b6ba8376d8bb90c1cb71d963e8165ef873820b/charts/ingress-nginx/values.yaml#L291-L303)
        1. [kubernetes/ingress-nginx](https://github.com/kubernetes/ingress-nginx/blob/0d2c6db75e47f81a6472f87e546072c75ad9f77d/docs/user-guide/tls.md#ssl-passthrough)
        1. [kubernetes/ingress-nginx](https://github.com/kubernetes/ingress-nginx/tree/master/charts/ingress-nginx)
        1. [controller.enableTLSPassthrough](https://docs.nginx.com/nginx-ingress-controller/installation/installation-with-helm/)

1. [discuss] docker repo, using personal now
    1. https://hub.docker.com/r/wzyahoo/athenz-zms-server/tags
1. [discuss] zms/status === liveness/readiness @@
1. [discuss] ZMS resources default
1. [yes/no] need PVC for ZMS?
    1. can export log using sidecar
1. [yes/no] need metric support?
1. [yes/no] add debug flag, change log level?
1. [confirm] using external DB?
1. `extraProp` to overwrite athenz.proporties
1. [later] duplicated template in `_helpers.tpl`
    1. seems can be fixed (study later)
        1. [Getting Title at 28:53](https://github.com/bitnami/charts/blob/6b59bd8ca6fcafbfb27e611182b4d4c9c1bf122d/bitnami/wordpress/templates/_helpers.tpl#L204-L215)
    1. [Usable sub-charts templates from parent chart · Issue #3920 · helm/helm](https://github.com/helm/helm/issues/3920)
    1. [How can you call a helm &#x27;helper&#x27; template from a subchart with the correct context?](https://stackoverflow.com/questions/47791971/how-can-you-call-a-helm-helper-template-from-a-subchart-with-the-correct-conte)
    1. as helm has problems to use templates across charts, we have to copy subcharts template to parent chart. (may break depenedency if the subchart updated)
    1. P.S. value supports only scalar (no code)
1. about DB
    1. [yes/no] need to enable SSL
    1. [later] `injectSecretsAsVolume=true` not working

## reference

- [bitnami/charts](https://github.com/bitnami/charts/blob/master/bitnami/wordpress/templates/deployment.yaml)
- [bitnami/charts](https://github.com/bitnami/charts/blob/master/bitnami/mariadb/templates/master-statefulset.yaml)
- [kubernetes/ingress-nginx](https://github.com/kubernetes/ingress-nginx/blob/master/charts/ingress-nginx/values.yaml)
