# Design concerns

1. metric name format
    1. `{namespace}_{metric}_{unit}`
        1. namespace = set by system properties
        1. metric hard coded inside Athenz
        1. unit = `total` or `seconds`
    1. reference: [Metric and label naming | Prometheus](https://prometheus.io/docs/practices/naming/#metric-names)
1. labels for `requestDomainName` and `principalDomainName`
    1. disable by default
    1. reasons
        1. not a suggested way in Prometheus
            - [Instrumentation#Use labels | Prometheus](https://prometheus.io/docs/practices/instrumentation/#use-labels)
            - [Instrumentation#Do not overuse labels | Prometheus](https://prometheus.io/docs/practices/instrumentation/#do-not-overuse-labels)
        1. the response's size of the `/metrics` request will become very large, causing bandwidth/latency problem at the prometheus side
            - [performance test result](./performance.md#without-domain-vs-with-2000-domain-prometheus-endpoint)
1. Prometheus pull as default
    1. require same network (Prometheus server, Athenz server)
    1. the suggested deployment for Prometheus
    1. open firewall port for Grafana for query from prometheus server
