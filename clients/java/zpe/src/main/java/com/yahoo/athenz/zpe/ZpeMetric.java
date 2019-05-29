/*
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

import com.yahoo.athenz.zts.DomainMetric;
import com.yahoo.athenz.zts.DomainMetricType;
import com.yahoo.athenz.zts.DomainMetrics;
import com.yahoo.rdl.JSON;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.TimerTask;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicIntegerArray;
import java.util.ArrayList;
import java.util.Timer;

public class ZpeMetric {
    
    public static final String ZPE_METRIC_FILE_PATH = "/var/zpe_stat/";
    public static final String ZPE_WRITE_INTERVAL = "3600000";
    
    public ConcurrentHashMap<String, AtomicIntegerArray> counter = new ConcurrentHashMap<>();
    private static volatile Timer FETCH_TIMER;
    private static final Object TIMER_LOCK = new Object();
    static boolean statsEnabled = Boolean.parseBoolean(System.getProperty(ZpeConsts.ZPE_PROP_STATS_ENABLED, "false"));
    
    //constructor
    ZpeMetric() {
        File directory = new File(String.valueOf(getFilePath()));
        //noinspection ResultOfMethodCallIgnored
        directory.mkdir();
        //setting the timer to the interval specified in the system property
        if (statsEnabled) {
            Integer interval = Integer.parseInt(System.getProperty(ZpeConsts.ZPE_PROP_METRIC_WRITE_INTERVAL, ZPE_WRITE_INTERVAL));
            Timer timer = FETCH_TIMER;
            if (timer == null) {
                synchronized (TIMER_LOCK) {
                    timer = FETCH_TIMER;
                    if (timer == null) {
                        timer = new Timer();
                        timer.schedule(new SchedulerService(), interval, interval);
                        FETCH_TIMER = timer;
                    }
                }
            }
        }
    }

    //scheduler service
    class SchedulerService extends TimerTask {
        @Override
        public void run() {
            writeToFile();
        }
    }

    String getFilePath() {
        String rootDir = System.getenv("ROOT");
        if (rootDir == null) {
            rootDir = "/home/athenz";
        }
        final String defaultPath = rootDir + ZPE_METRIC_FILE_PATH;
        String filePath = System.getProperty(ZpeConsts.ZPE_PROP_METRIC_FILE_PATH, defaultPath);
        
        // verify it ends with / and handle accordingly
        
        if (!filePath.endsWith(File.separator)) {
            filePath = filePath.concat(File.separator);
        }
        return filePath;
    }

    //to increment a metric counter by 1
    public void increment(String metricName, String domainName) {
        if (statsEnabled) {
            if (!counter.containsKey(domainName)) {
                counter.putIfAbsent(domainName, new AtomicIntegerArray(DomainMetricType.LOAD_DOMAIN_GOOD.ordinal() + 1));
            }
            Integer index = com.yahoo.athenz.zts.DomainMetricType.valueOf(metricName).ordinal();
            counter.get(domainName).incrementAndGet(index);
        }
    }

    //to convert the atomicIntegerArray to JSON object
    public DomainMetrics getMetrics(String domainName) {
        ArrayList<DomainMetric> metricList = new ArrayList<>();
        for (DomainMetricType label : DomainMetricType.values()) {
            DomainMetric domainMetric = new DomainMetric();
            domainMetric.setMetricType(label);
            domainMetric.setMetricVal(counter.get(domainName).getAndSet(label.ordinal(), 0));
            metricList.add(domainMetric);
        }
        return new DomainMetrics().setDomainName(domainName).setMetricList(metricList);
    }

    //to write the JSON to file
    public void writeToFile() {
        final String dirPath = getFilePath();
        for (String domainName : counter.keySet()) {
            DomainMetrics domainMetrics = getMetrics(domainName);
            Long epoch = System.currentTimeMillis();
            String filepath = dirPath + domainName + "_" + Long.toString(epoch) + ".json";
            try {
                Path path = Paths.get(filepath);
                Files.write(path, JSON.bytes(domainMetrics));
            } catch (IOException e) {
                counter.remove(domainName);
            }
        }
    }
}
