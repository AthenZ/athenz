# Athenz metric for Prometheus
Athenz Yahoo Server metrics interface implementation for Prometheus

<!-- TOC depthFrom:2 updateOnSave:true -->

- [Usage](#usage)
    - [Build](#build)
    - [Integrate with Athenz](#integrate-with-athenz)
- [Note](#note)
- [For developer](#for-developer)
    - [Test coverage](#test-coverage)
    - [Performance test result](#performance-test-result)
    - [Design concerns](#design-concerns)
    - [example main for integration test](#example-main-for-integration-test)

<!-- /TOC -->

<a id="markdown-usage" name="usage"></a>
## Usage

<a id="markdown-build" name="build"></a>
### Build
```bash
mvn clean package
ls ./target/athenz_metrics_prometheus-*.jar
```

<a id="markdown-integrate-with-athenz" name="integrate-with-athenz"></a>
### Integrate with Athenz
1. add `athenz_metrics_prometheus-*.jar` in Athenz server's classpath
1. overwrite existing system property
    ```properties
    # ZMS server
    athenz.zms.metric_factory_class=com.yahoo.athenz.common.metrics.impl.prometheus.PrometheusMetricFactory

    # ZTS server
    athenz.zts.metric_factory_class=com.yahoo.athenz.common.metrics.impl.prometheus.PrometheusMetricFactory
    ```
1. add system property for `PrometheusMetric`
    ```properties
    # enable PrometheusMetric class
    athenz.metrics.prometheus.enable=true
    # export JVM metrics
    athenz.metrics.prometheus.jvm.enable=true
    # the Prometheus /metrics endpoint
    athenz.metrics.prometheus.http_server.enable=true
    athenz.metrics.prometheus.http_server.port=8181
    # Prometheus metric prefix
    athenz.metrics.prometheus.namespace=athenz_zms
    # for dev. env. ONLY, record Athenz domain data as label
    athenz.metrics.prometheus.label.request_domain_name.enable=false
    athenz.metrics.prometheus.label.principal_domain_name.enable=false
    ```
1. verify setup: `curl localhost:8181/metrics`
1. add job in your Prometheus server
    ```yaml
    scrape_configs:
        - job_name: 'athenz-server'
            scrape_interval: 10s
            honor_labels: true
            static_configs:
                - targets: ['athenz.server.domain:8181']
    ```

<a id="markdown-note" name="note"></a>
## Note

1. The current implementation is based on specific [athenz version](./pom.xml#L31). As the athenz dependency is using the [provided scope](./pom.xml#L51), this class may throw error if non-compatible athenz JARs are included during runtime.

<a id="markdown-for-developer" name="for-developer"></a>
## For developer

<a id="markdown-test-coverage" name="test-coverage"></a>
### Test coverage
```bash
mvn clover:instrument clover:aggregate clover:clover clover:check
open ./target/site/clover/index.html
```

<a id="markdown-performance-test-result" name="performance-test-result"></a>
### Performance test result
- [performance.md](./doc/performance.md)

<a id="markdown-design-concerns" name="design-concerns"></a>
### Design concerns
- [design-concerns.md](./doc/design-concerns.md)

<a id="markdown-example-main-for-integration-test" name="example-main-for-integration-test"></a>
### example main for integration test
- [example-main.md](./doc/example-main.md)
