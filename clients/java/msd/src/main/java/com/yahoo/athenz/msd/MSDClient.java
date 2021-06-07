/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package com.yahoo.athenz.msd;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.jaxrs.json.JacksonJaxbJsonProvider;
import com.fasterxml.jackson.jaxrs.json.JacksonJsonProvider;
import java.io.Closeable;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLContext;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import org.glassfish.jersey.apache.connector.ApacheConnectorProvider;
import org.glassfish.jersey.client.ClientConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class MSDClient implements Closeable {

  private static final Logger LOGGER = LoggerFactory.getLogger(MSDClient.class);

  public static final String MSD_CLIENT_PROP_READ_TIMEOUT = "athenz.msd.client.read_timeout";
  public static final String MSD_CLIENT_PROP_CONNECT_TIMEOUT = "athenz.msd.client.connect_timeout";
  public static final String MSD_CLIENT_PROP_MSD_URL = "athenz.msd.client.msd_url";

  protected MSDRDLGeneratedClient client = null;

  /**
   * Constructs a new MSDClient object with the given SSLContext object
   * and MSD Server Url. Default read and connect timeout values are 30000ms (30sec).
   * The application can change these values by using the athenz.msd.client.read_timeout
   * and athenz.msd.client.connect_timeout system properties. The values specified
   * for timeouts must be in milliseconds.
   *
   * @param url        MSD Server url (e.g. https://server1.athenzcompany.com:4443/msd/v1)
   * @param sslContext SSLContext that includes service's private key and x.509 certificate
   *                   for authenticating requests
   */
  public MSDClient(String url, SSLContext sslContext) {

    // verify we have a valid ssl context specified

    if (sslContext == null) {
      throw new IllegalArgumentException("SSLContext object must be specified");
    }
    initClient(url, sslContext);
  }

  /**
   * Initialize the client for class constructors
   *
   * @param url        MSD Server url
   * @param sslContext SSLContext for service authentication
   */
  private void initClient(String url, SSLContext sslContext) {

    String msdUrl;
    if (url == null || "".equals(url)) {
      LOGGER.error("No MSD URL is specified. Trying to look in environment.");
      msdUrl = System.getProperty(MSD_CLIENT_PROP_MSD_URL);
      if (msdUrl == null || "".equals(msdUrl)) {
        throw new IllegalArgumentException("MSD URL must be specified");
      }
    } else {
      msdUrl = url;
    }

    /* determine our read and connect timeouts */

    int readTimeout = Integer.parseInt(System.getProperty(MSD_CLIENT_PROP_READ_TIMEOUT, "30000"));
    int connectTimeout = Integer.parseInt(System.getProperty(MSD_CLIENT_PROP_CONNECT_TIMEOUT, "30000"));

    ClientBuilder builder = getClientBuilder();
    builder = builder.sslContext(sslContext);

    final JacksonJsonProvider jacksonJsonProvider = new JacksonJaxbJsonProvider()
        .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    ClientConfig clientConfig = new ClientConfig(jacksonJsonProvider);
    clientConfig.connectorProvider(new ApacheConnectorProvider());

    // JerseyClientBuilder::withConfig() replaces the existing config with the new client
    // config. Hence the client config should be added to the builder before the timeouts.
    // Otherwise the timeout settings would be overridden.
    Client rsClient =
        builder
            .withConfig(clientConfig)
            .connectTimeout(connectTimeout, TimeUnit.MILLISECONDS)
            .readTimeout(readTimeout, TimeUnit.MILLISECONDS)
            .build();

    client = new MSDRDLGeneratedClient(msdUrl, rsClient);
  }

  ClientBuilder getClientBuilder() {
    return ClientBuilder.newBuilder();
  }

  /**
   * Retrieve the list of all micro segmentation policies from the MSD Server.
   * It will pass an optional matchingTag so that MSD can skip returning policies
   * if no changes have taken place since that tag was issued.
   *
   * @param matchingTag     (can be null) contains modified timestamp received
   *                        with last request. If null, then return all micro segmentation policies.
   * @param responseHeaders contains the "tag" returned for modification
   *                        time of the micro segmentation policies, map key = "tag", List should
   *                        contain a single value timestamp String to be used
   *                        with subsequent call as matchingTag to this API
   * @return list of micro segmentation policies
   * @throws MSDClientException in case of failure
   */
  public TransportPolicyRules getTransportPolicyRules(String matchingTag,
      Map<String, List<String>> responseHeaders) {
    try {
      return client.getTransportPolicyRules(matchingTag, responseHeaders);
    } catch (ResourceException ex) {
      throw new MSDClientException(ex.getCode(), ex.getData());
    } catch (Exception ex) {
      throw new MSDClientException(ResourceException.BAD_REQUEST, ex.getMessage());
    }
  }

  /**
   * Retrieve list of workloads running on the given ip address
   * @param ipAddress ip address of the workload
   * @param matchingTag     (can be null) contains modified timestamp received
   *                        with last request. If null, then return all workloads for given ip.
   * @param responseHeaders contains the "tag" returned for modification
   *                        time of the workloads, map key = "tag", List should
   *                        contain a single value timestamp String to be used
   *                        with subsequent call as matchingTag to this API
   * @return list of workloads on success. MSDClientException will be thrown in case of failure
   */
  public Workloads getWorkloadsByIP(String ipAddress, String matchingTag,
                                    Map<String, List<String>> responseHeaders) {
    try {
      return client.getWorkloadsByIP(ipAddress, matchingTag, responseHeaders);
    } catch (ResourceException ex) {
      throw new MSDClientException(ex.getCode(), ex.getData());
    } catch (Exception ex) {
      throw new MSDClientException(ResourceException.BAD_REQUEST, ex.getMessage());
    }
  }

  /**
   * Retrieve list of workloads running with given domain and service
   * @param domain name of the domain
   * @param service name of the service
   * @param matchingTag     (can be null) contains modified timestamp received
   *                        with last request. If null, then return all workloads for given domain and service.
   * @param responseHeaders contains the "tag" returned for modification
   *                        time of the workloads, map key = "tag", List should
   *                        contain a single value timestamp String to be used
   *                        with subsequent call as matchingTag to this API
   * @return list of workloads on success. MSDClientException will be thrown in case of failure
   */
  public Workloads getWorkloadsByService(String domain, String service, String matchingTag,
                                         Map<String, List<String>> responseHeaders) {
    try {
      return client.getWorkloadsByService(domain, service, matchingTag, responseHeaders);
    } catch (ResourceException ex) {
      throw new MSDClientException(ex.getCode(), ex.getData());
    } catch (Exception ex) {
      throw new MSDClientException(ResourceException.BAD_REQUEST, ex.getMessage());
    }
  }

  /**
   * Close the MSDClient object and release any allocated resources.
   */
  @Override
  public void close() {
    client.close();
  }
}
