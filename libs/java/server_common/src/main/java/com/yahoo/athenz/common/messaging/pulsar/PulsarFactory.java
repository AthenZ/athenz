/*
 *
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
 *
 */

package com.yahoo.athenz.common.messaging.pulsar;

import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.common.messaging.ChangePublisher;
import com.yahoo.athenz.common.messaging.ChangePublisherFactory;
import com.yahoo.athenz.common.messaging.ChangeSubscriber;
import com.yahoo.athenz.common.messaging.ChangeSubscriberFactory;
import com.yahoo.athenz.common.messaging.pulsar.client.AthenzPulsarClient;
import org.apache.pulsar.client.api.SubscriptionType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.invoke.MethodHandles;

public class PulsarFactory<T> implements ChangePublisherFactory<T>, ChangeSubscriberFactory<T> {
  public static final String PROP_MESSAGING_CLI_SERVICE_URL = "athenz.messaging_cli.service_url";
  public static final String PROP_MESSAGING_CLI_KEY_PATH = "athenz.messaging_cli.key_path";
  public static final String PROP_MESSAGING_CLI_CERT_PATH = "athenz.messaging_cli.cert_path";
  public static final String PROP_MESSAGING_CLI_TRUST_STORE_PATH = "athenz.messaging_cli.truststore_path";

  private static final Logger LOG = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

  protected static AthenzPulsarClient.TlsConfig tlsConfig() {
    String tlsCertPath = System.getProperty(PROP_MESSAGING_CLI_CERT_PATH);
    String tlsKeyPath = System.getProperty(PROP_MESSAGING_CLI_KEY_PATH);
    String tlsCaPath = System.getProperty(PROP_MESSAGING_CLI_TRUST_STORE_PATH);

    if (tlsCertPath == null || tlsKeyPath == null || tlsCaPath == null) {
      LOG.error("Pulsar client configuration invalid. tlsCertPath :[{}]. tlsKeyPath : [{}], tlsCaPath: [{}]", tlsCertPath, tlsKeyPath, tlsCaPath);
      throw new IllegalArgumentException("invalid settings configured");
    }

    return new AthenzPulsarClient.TlsConfig(tlsCertPath, tlsKeyPath, tlsCaPath);
  }

  protected static String serviceUrl() {
    String serviceUrl = System.getProperty(PROP_MESSAGING_CLI_SERVICE_URL);

    if (serviceUrl == null) {
      LOG.error("Pulsar client null service url");
      throw new IllegalArgumentException("invalid pulsar service url");
    }

    return serviceUrl;
  }

  @Override
  public ChangePublisher<T> create(PrivateKeyStore keyStore, String topicName) {
    LOG.error("creating a pulsar change publisher");
    return new PulsarChangePublisher<>(serviceUrl(), topicName, tlsConfig());
  }

  @Override
  public ChangeSubscriber<T> create(PrivateKeyStore keyStore, String topicName, String subscriptionName, String subscriptionTypeAsString) {
    return new PulsarChangeSubscriber<>(serviceUrl(), topicName, subscriptionName, toSubscriptionType(subscriptionTypeAsString), tlsConfig());
  }

  private SubscriptionType toSubscriptionType(String subscriptionType) {
    return SubscriptionType.valueOf(subscriptionType);
  }
}
