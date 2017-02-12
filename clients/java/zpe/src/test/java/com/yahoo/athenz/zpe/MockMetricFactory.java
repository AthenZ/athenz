/**
 * Copyright 2016 Yahoo Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.yahoo.athenz.zpe;

import java.util.Map;

import com.yahoo.athenz.common.metrics.Metric;
import com.yahoo.athenz.common.metrics.MetricFactory;

import java.util.HashMap;

public class MockMetricFactory implements MetricFactory {

    @Override
    public Metric create() {
        return new MockMetric();
    }

    public static class MockMetric implements Metric {

        Map<String, Integer> metricMap = new HashMap<>(); 

        public void increment(String metric, int count) {
            Integer mcnt = metricMap.get(metric);
            if (mcnt == null) {
                metricMap.put(metric, new Integer(count));
            } else {
                int cnt = mcnt.intValue() + count;
                metricMap.put(metric, new Integer(cnt));
            }
        }

        @Override
        public void increment(String metric) {
            increment(metric, 1);
        }
        
        @Override
        public void increment(String metric, String domainName) {
            increment(metric + domainName, 1);
        }
        
        @Override
        public void increment(String metric, String domainName, int count) {
            increment(metric + domainName, count);
        }
        
        public int metricCount(String metric) {
            Integer icnt = metricMap.get(metric);
            if (icnt == null) {
                return -1;
            }
            return icnt.intValue();
        }
        public int metricCount(String metric, String domainName) {
            return metricCount(metric + domainName);
        }

        @Override
        public Object startTiming(String metric, String domainName) {
            return null;
        }

        @Override
        public void stopTiming(Object timerMetric) {
        }
    
        @Override
        public void flush() {
            metricMap.clear();
        }
        
        @Override
        public void quit() {
            metricMap.clear();
        }
    }
}

