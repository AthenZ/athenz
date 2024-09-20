/*
 * Copyright The Athenz Authors
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
package io.athenz.server.aws.common;

import org.eclipse.jetty.util.StringUtil;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;

import java.util.*;

public class ServerCommonTestUtils {

    public static Map<String, AttributeValue> generateAttributeValues(final String service,
            final String instanceId, final String currentTime, final String lastNotifiedTime,
            final String lastNotifiedServer, final String expiryTime, final String hostName) {

        String provider = "provider";
        String primaryKey = provider + ":" + service + ":" + instanceId;
        Map<String, AttributeValue> item = new HashMap<>();
        item.put("primaryKey", AttributeValue.fromS(primaryKey));
        item.put("service", AttributeValue.fromS(service));
        item.put("provider", AttributeValue.fromS(provider));
        item.put("instanceId", AttributeValue.fromS(instanceId));
        item.put("currentSerial", AttributeValue.fromS("currentSerial"));

        AttributeValue currentTimeVal = AttributeValue.fromN(currentTime);

        if (!StringUtil.isEmpty(currentTime)) {
            item.put("currentTime", currentTimeVal);
            item.put("prevTime", currentTimeVal);
        }

        item.put("currentIP", AttributeValue.fromS("currentIP"));
        item.put("prevSerial", AttributeValue.fromS("prevSerial"));
        item.put("prevIP", AttributeValue.fromS("prevIP"));

        item.put("clientCert", AttributeValue.fromBool(false));

        if (!StringUtil.isEmpty(lastNotifiedTime)) {
            item.put("lastNotifiedTime", AttributeValue.fromN(lastNotifiedTime));
        }

        if (!StringUtil.isEmpty(lastNotifiedServer)) {
            item.put("lastNotifiedServer", AttributeValue.fromS(lastNotifiedServer));
        }

        if (!StringUtil.isEmpty(expiryTime)) {
            item.put("expiryTime", AttributeValue.fromN(expiryTime));
        }

        if (!StringUtil.isEmpty(hostName)) {
            item.put("hostName", AttributeValue.fromS(hostName));
        }

        return item;
    }

    public static Map<String, AttributeValue> generateWorkloadAttributeValues(final String service,
            final String instanceId, final String provider, final String ip, final String hostname,
            final String creationTime, final String updateTime, final String certExpiryTime) {

        String primaryKey = service + "#" + instanceId + "#" + ip;
        Map<String, AttributeValue> item = new HashMap<>();
        item.put("primaryKey", AttributeValue.fromS(primaryKey));
        item.put("service", AttributeValue.fromS(service));
        item.put("provider", AttributeValue.fromS(provider));
        item.put("instanceId", AttributeValue.fromS(instanceId));
        item.put("ip", AttributeValue.fromS(ip));
        item.put("hostname", AttributeValue.fromS(hostname));
        item.put("creationTime", AttributeValue.fromN(creationTime));
        item.put("updateTime", AttributeValue.fromN(updateTime));
        item.put("certExpiryTime", AttributeValue.fromN(certExpiryTime));

        return item;
    }
}
