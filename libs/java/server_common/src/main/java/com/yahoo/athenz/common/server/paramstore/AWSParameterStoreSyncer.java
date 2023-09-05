/*
 *
 *  * Copyright The Athenz Authors
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *     http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package com.yahoo.athenz.common.server.paramstore;

import com.amazonaws.util.EC2MetadataUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.ssm.SsmClient;
import software.amazon.awssdk.services.ssm.model.*;

import java.lang.invoke.MethodHandles;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.StampedLock;

/**
 * Periodically (configurable) loads all AWS Parameters Store and store it in memory.
 * Provides api to retrieve the parameters.
 * <p>
 * Required permissions: ssm:GetParameters, ssm:DescribeParameters
 */
public class AWSParameterStoreSyncer implements DynamicParameterStore {

    private static final Logger LOG = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    static final String PROP_RELOAD_PARAMS_PERIOD = "athenz.common.server.paramstore.reload_period";
    private static final String RELOAD_PARAMS_SECONDS_DEFAULT = "60";
    
    // comma separated list of prefixes to be loaded from parameter store
    static final String PROP_PARAMETER_STORE_PARAM_PREFIX_LIST = "athenz.common.server.paramstore.prefix_list";
    private final String[] parameterPrefixArray;

    final SsmClient ssmClient;

    // Since this is a single-writer and multiple-reader, 
    // use StampedLock because it is lock-free for readers in most cases.
    private final StampedLock lock = new StampedLock();
    private final Map<String, ParameterHolder> parameterMap = new HashMap<>();

    public AWSParameterStoreSyncer() {
        parameterPrefixArray = loadParamPrefixes();
        ssmClient = initClient();
        reloadParameters();
        startReloadParamsTask();
    }

    private String[] loadParamPrefixes() {
        String prefixProp = System.getProperty(PROP_PARAMETER_STORE_PARAM_PREFIX_LIST);
        if (prefixProp == null) {
            return null;
        }
        return prefixProp.split(",");
    }

    SsmClient initClient() {
        try {
            String region = EC2MetadataUtils.getInstanceInfo().getRegion();
            return SsmClient.builder()
                .region(Region.of(region))
                .build();
        } catch (Exception ex) {
            LOG.error("Failed to init aws ssm client", ex);
        }
        return null;
    }

    private void startReloadParamsTask() {
        // do not initiate reloadParameters task if ssm client is null
        if (ssmClient != null) {
            ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor();

            long periodBetweenExecutions = Long.parseLong(
                    System.getProperty(PROP_RELOAD_PARAMS_PERIOD, RELOAD_PARAMS_SECONDS_DEFAULT));

            executor.scheduleAtFixedRate(this::reloadParameters,
                    periodBetweenExecutions, periodBetweenExecutions, TimeUnit.SECONDS);
        }
    }

    private void reloadParameters() {
        if (ssmClient == null) {
            LOG.error("Cannot reload AWS Parameters store, ssm client is null");
            return;
        }
        try {
            storeParameters(getParameterList());
        } catch (Exception ex) {
            LOG.error("Failed to reload AWS Parameters store", ex);
        }
    }

    void storeParameters(List<ParameterMetadata> params) {
        for (ParameterMetadata param : params) {
            if (shouldFetchParam(param)) {
                String paramName = param.name();
                GetParameterRequest req = GetParameterRequest.builder()
                    .name(paramName)
                    .withDecryption(true)
                    .build();
                GetParameterResponse res = ssmClient.getParameter(req);

                String paramValue = res.parameter().value();
                Instant paramLastModified = res.parameter().lastModifiedDate();
                writeParameter(paramName, paramValue, paramLastModified);
                LOG.info("AWSParameterStoreSyncer update map, name: [{}], value: [{}], modification time: [{}]", paramName, paramValue, paramLastModified);
            }
        }
    }

    private boolean shouldFetchParam(ParameterMetadata param) {
        if (readParameter(param.name()) == null) {
            return true;
        }
        return readParameter(param.name()).lastModifiedDate.isBefore(param.lastModifiedDate());
    }

    private List<ParameterMetadata> getParameterList() {

        DescribeParametersRequest request;
        if (parameterPrefixArray != null) {
            request = DescribeParametersRequest.builder()
                .filters(ParametersFilter.builder()
                    .key("Name")
                    .values(parameterPrefixArray)
                    .build())
                .build();
        } else {
            request = DescribeParametersRequest.builder().build();
        }
        DescribeParametersResponse result = ssmClient.describeParameters(request);
        return result.parameters();
    }


    @Override
    public String get(String param) {
        return get(param, null);
    }

    @Override
    public String get(String param, String defaultValue) {
        ParameterHolder paramHolder = readParameter(param);
        return paramHolder == null ? defaultValue : paramHolder.value;
    }

    void writeParameter(String paramName, String paramValue, Instant paramLastModified) {
        long stamp = lock.writeLock();
        try {
            parameterMap.put(paramName, new ParameterHolder(paramValue, paramLastModified));
        } finally {
            lock.unlockWrite(stamp);
        }
    }

    ParameterHolder readParameter(String key) {
        long stamp = lock.tryOptimisticRead();
        ParameterHolder value = parameterMap.get(key);

        if (!lock.validate(stamp)) {
            stamp = lock.readLock();
            try {
                return parameterMap.get(key);
            } finally {
                lock.unlock(stamp);
            }
        }
        return value;
    }

    static class ParameterHolder {
        public ParameterHolder(String value, Instant lastModifiedDate) {
            this.value = value;
            this.lastModifiedDate = lastModifiedDate;
        }

        String value;
        Instant lastModifiedDate;
    }
}
