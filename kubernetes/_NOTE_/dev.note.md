
<a id="markdown-dev-note" name="dev-note"></a>
# DEV note

<!-- TOC -->

- [DEV note](#dev-note)
    - [links](#links)
    - [helm syntax](#helm-syntax)
    - [docker push](#docker-push)

<!-- /TOC -->

<a id="markdown-links" name="links"></a>
## links

- images
    - [Docker Hub](https://hub.docker.com/repositories)
- helm
    - [Accessing Files Inside Templates](https://helm.sh/docs/chart_template_guide/accessing_files/)
    - [Built-in Objects](https://helm.sh/docs/chart_template_guide/builtin_objects/#helm)
    - [Subcharts and Global Values](https://helm.sh/docs/chart_template_guide/subcharts_and_globals/)
- example
    - [Kubernetes Patterns - Application process management](https://www.magalix.com/blog/kubernetes-patterns-application-process-management-1)
    - [Starting containers in order on Kubernetes with InitContainers](https://medium.com/@xcoulon/initializing-containers-in-order-with-kubernetes-18173b9cc222)
    - [Configuring Java Apps With Kubernetes ConfigMaps and Helm - DZone Microservices](https://dzone.com/articles/configuring-java-apps-with-kubernetes-configmaps-a)
    - [Helm from basics to advanced — part II](https://banzaicloud.com/blog/creating-helm-charts-part-2/)
    - [The Art of the Helm Chart: Patterns from the Official Kubernetes Charts | Hacker Noon](https://hackernoon.com/the-art-of-the-helm-chart-patterns-from-the-official-kubernetes-charts-8a7cafa86d12)
- mariadb
    - https://github.com/bitnami/charts/tree/master/bitnami/mariadb
    - https://github.com/bitnami/charts/blob/master/bitnami/mariadb/values.yaml
- helm SSL
    - [Gen certificate in Helm](https://medium.com/nuvo-group-tech/move-your-certs-to-helm-4f5f61338aca)
- helm helper
    - [Convert yaml to property file in helm template](https://stackoverflow.com/questions/60184221/convert-yaml-to-property-file-in-helm-template)
- ingress
    - [Ingress nginx for TCP and UDP services](https://minikube.sigs.k8s.io/docs/tutorials/nginx_tcp_udp_ingress/)
    - keycloak
        - https://github.com/helm/charts/blob/master/stable/keycloak/values.yaml#L187-L206
        - https://github.com/helm/charts/blob/master/stable/keycloak/templates/ingress.yaml




<a id="markdown-helm-syntax" name="helm-syntax"></a>
## helm syntax

1. `{{` V.S. `{{-`
    1. `{{- (with the dash and space added) indicates that whitespace should be chomped left, while -}} means whitespace to the right should be consumed`
    1. [Flow Control](https://helm.sh/docs/chart_template_guide/control_structures/#controlling-whitespace)
1. helm comment
    ```yaml
    {{- /*
    This is a comment.
    */ -}}
    ```
1. `.` V.S. `$`
    1. `there is one variable that is always global - $ - this variable will always point to the root context`
    1. [Variables](https://helm.sh/docs/chart_template_guide/variables/)

<a id="markdown-docker-push" name="docker-push"></a>
## docker push

```bash
docker tag athenz-zms-server wzyahoo/athenz-zms-server:latest
docker push wzyahoo/athenz-zms-server
docker tag athenz-zts-server wzyahoo/athenz-zts-server:latest
docker push wzyahoo/athenz-zts-server

docker tag athenz-setup-env wzyahoo/athenz-setup-env:latest
docker push wzyahoo/athenz-setup-env
```
