# Example main

`Main.java`
```java
package com.yahoo.athenz.common.metrics;

import com.yahoo.athenz.common.metrics.Metric;
import com.yahoo.athenz.common.metrics.impl.prometheus.PrometheusMetricFactory;

public class Main {
    public static void main(String[] args) throws InterruptedException {
        System.out.println("PrometheusMetric start");

        PrometheusMetricFactory pmf = new PrometheusMetricFactory();
        Metric pm = pmf.create();

        // counter
        pm.increment("request_no_label");
        pm.increment("request01", null, 5);
        pm.increment("request01", "domain01", 10);
        pm.increment("request01", "domain02", 20);

        // timer
        Object timer = pm.startTiming("timer_test", null);
        Thread.sleep(99L);
        pm.stopTiming(timer);

        Object timerD = pm.startTiming("timer_test_domain", "domain01");
        Thread.sleep(111L);
        pm.stopTiming(timerD);

        // flush
        System.out.println("before flush...");
        pm.flush();
        System.out.println("If you are using pull exporter, run 'curl localhost:8181/metrics' to verify");

        // quit
        System.out.println("wait 1 min, before quit...");
        Thread.sleep(1L * 1000 * 60);
        pm.quit();
    }
}
```

## Run
```bash
cat > "$(git rev-parse --show-toplevel)/contributions/metric/prometheus/src/main/java/com/yahoo/athenz/common/metrics/Main.java"
# copy and paste the Main.java's content
cd "$(git rev-parse --show-toplevel)/contributions/metric/prometheus"
mvn package exec:java -Dexec.mainClass="com.yahoo.athenz.common.metrics.Main"
```

## sample output (with default values)
```bash
$ curl localhost:8181/metrics
# HELP athenz_server_request_no_label_total request_no_label_total
# TYPE athenz_server_request_no_label_total counter
athenz_server_request_no_label_total{domain="",principal="",} 1.0
# HELP athenz_server_request01_total request01_total
# TYPE athenz_server_request01_total counter
athenz_server_request01_total{domain="",principal="",} 35.0
# HELP athenz_server_timer_test_domain_seconds timer_test_domain_seconds
# TYPE athenz_server_timer_test_domain_seconds summary
athenz_server_timer_test_domain_seconds_count{domain="",principal="",} 1.0
athenz_server_timer_test_domain_seconds_sum{domain="",principal="",} 0.113545231
# HELP athenz_server_timer_test_seconds timer_test_seconds
# TYPE athenz_server_timer_test_seconds summary
athenz_server_timer_test_seconds_count{domain="",principal="",} 1.0
athenz_server_timer_test_seconds_sum{domain="",principal="",} 0.101996235
```
