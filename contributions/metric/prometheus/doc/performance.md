# Test Summary

## NoOps V.S. Prometheus (Athenz endpoint)
- [Using NoOpMetric](./assets/jmeter/no_ops/summary.csv)
- [Using PrometheusMetric](./assets/jmeter/prometheus/summary.csv)

### Conclusion
- Throughput: (499-510)/510 * 100% = `-2.16%`
- **not much performance impact on existing API**

## without domain V.S. with 2000 domain (prometheus endpoint)
- [label disabled](./assets/jmeter/metric-no-label/summary.csv)
- [label enabled, with 2000 domain as label](./assets/jmeter/metric-2000-domain/summary.csv)

### Conclusion
- Throughput: (4-44)/44 * 100% = `-90.9%`
- **should not enable metric label for Athenz domain**
