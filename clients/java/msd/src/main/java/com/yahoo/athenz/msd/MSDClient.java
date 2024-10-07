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

import java.io.Closeable;
import java.util.List;
import java.util.Map;
import javax.net.ssl.SSLContext;

import org.apache.hc.client5.http.config.ConnectionConfig;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.config.TlsConfig;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.ssl.DefaultClientTlsStrategy;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.ssl.TlsSocketStrategy;
import org.apache.hc.core5.http.ssl.TLS;
import org.apache.hc.core5.pool.PoolConcurrencyPolicy;
import org.apache.hc.core5.pool.PoolReusePolicy;
import org.apache.hc.core5.util.TimeValue;
import org.apache.hc.core5.util.Timeout;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class MSDClient implements Closeable {

    private static final Logger LOGGER = LoggerFactory.getLogger(MSDClient.class);

    public static final String MSD_CLIENT_PROP_READ_TIMEOUT = "athenz.msd.client.read_timeout";
    public static final String MSD_CLIENT_PROP_CONNECT_TIMEOUT = "athenz.msd.client.connect_timeout";
    public static final String MSD_CLIENT_PROP_MSD_URL = "athenz.msd.client.msd_url";
    public static final String MSD_CLIENT_PROP_POOL_MAX_PER_ROUTE = "athenz.msd.client.http_pool_max_per_route";
    public static final String MSD_CLIENT_PROP_POOL_MAX_TOTAL = "athenz.msd.client.http_pool_max_total";
    public static final String MSD_CLIENT_PROP_TIME_TO_LIVE = "athenz.msd.client.http_pool_time_to_live";
    public static final String MSD_CLIENT_PROP_HANDSHAKE_TIMEOUT = "athenz.msd.client.handshake_timeout";

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

    protected PoolingHttpClientConnectionManager createConnectionPooling(SSLContext sslContext) {

        int maxPerRoute = Integer.parseInt(System.getProperty(MSD_CLIENT_PROP_POOL_MAX_PER_ROUTE, "2"));
        int maxTotal = Integer.parseInt(System.getProperty(MSD_CLIENT_PROP_POOL_MAX_TOTAL, "20"));
        int readTimeout = Integer.parseInt(System.getProperty(MSD_CLIENT_PROP_READ_TIMEOUT, "30000"));
        int connectTimeout = Integer.parseInt(System.getProperty(MSD_CLIENT_PROP_CONNECT_TIMEOUT, "30000"));
        int timeToLive = Integer.parseInt(System.getProperty(MSD_CLIENT_PROP_TIME_TO_LIVE, "10"));
        int handshakeTimeout = Integer.parseInt(System.getProperty(MSD_CLIENT_PROP_HANDSHAKE_TIMEOUT, "30000"));

        final TlsSocketStrategy tlsStrategy = new DefaultClientTlsStrategy(sslContext);

        return PoolingHttpClientConnectionManagerBuilder.create()
                .setTlsSocketStrategy(tlsStrategy)
                .setDefaultTlsConfig(TlsConfig.custom()
                        .setHandshakeTimeout(Timeout.ofMilliseconds(handshakeTimeout))
                        .setSupportedProtocols(TLS.V_1_2, TLS.V_1_3)
                        .build())
                .setPoolConcurrencyPolicy(PoolConcurrencyPolicy.STRICT)
                .setConnPoolPolicy(PoolReusePolicy.LIFO)
                .setDefaultConnectionConfig(ConnectionConfig.custom()
                        .setSocketTimeout(Timeout.ofMilliseconds(readTimeout))
                        .setConnectTimeout(Timeout.ofMilliseconds(connectTimeout))
                        .setTimeToLive(TimeValue.ofMinutes(timeToLive))
                        .build())
                .setMaxConnPerRoute(maxPerRoute)
                .setMaxConnTotal(maxTotal)
                .build();
    }

    protected CloseableHttpClient createHttpClient(PoolingHttpClientConnectionManager poolingHttpClientConnectionManager) {

        RequestConfig config = RequestConfig.custom()
                .setRedirectsEnabled(false)
                .build();
        return HttpClients.custom()
                .setConnectionManager(poolingHttpClientConnectionManager)
                .setDefaultRequestConfig(config)
                .build();
    }

    /**
     * Initialize the client for class constructors
     *
     * @param url        MSD Server url
     * @param sslContext SSLContext for service authentication
     */
    private void initClient(String url, SSLContext sslContext) {

        String msdUrl;
        if (url == null || url.isEmpty()) {
            LOGGER.error("No MSD URL is specified. Trying to look in environment.");
            msdUrl = System.getProperty(MSD_CLIENT_PROP_MSD_URL);
            if (msdUrl == null || msdUrl.isEmpty()) {
                throw new IllegalArgumentException("MSD URL must be specified");
            }
        } else {
            msdUrl = url;
        }

        PoolingHttpClientConnectionManager connManager = createConnectionPooling(sslContext);
        CloseableHttpClient httpClient = createHttpClient(connManager);

        client = new MSDRDLGeneratedClient(msdUrl, httpClient);
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
        } catch (ClientResourceException ex) {
            throw new MSDClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new MSDClientException(ClientResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Retrieve list of workloads running on the given ip address
     *
     * @param ipAddress       ip address of the workload
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
        } catch (ClientResourceException ex) {
            throw new MSDClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new MSDClientException(ClientResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Retrieve list of workloads running with given domain and service
     *
     * @param domain          name of the domain
     * @param service         name of the service
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
        } catch (ClientResourceException ex) {
            throw new MSDClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new MSDClientException(ClientResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Api to perform a dynamic workload PUT operation for a domain and service
     *
     * @param domain  name of the domain
     * @param service name of the service
     * @param options options for the new workload
     * @return WorkloadOptions
     */
    public WorkloadOptions putDynamicWorkload(String domain, String service, WorkloadOptions options, String resourceOwner) {
        try {
            return client.putDynamicWorkload(domain, service, options, resourceOwner);
        } catch (ClientResourceException ex) {
            throw new MSDClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new MSDClientException(ClientResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Api to perform a dynamic workload Delete operation for a domain, service and name
     *
     * @param domain  name of the domain
     * @param service name of the service
     * @param instanceId instanceId of the host
     */
    public void deleteDynamicWorkload(String domain, String service, String instanceId, String resourceOwner) {
        try {
            client.deleteDynamicWorkload(domain, service, instanceId, resourceOwner);
        } catch (ClientResourceException ex) {
            throw new MSDClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new MSDClientException(ClientResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Api to perform a static workload PUT operation for a domain and service
     *
     * @param domain         name of the domain
     * @param service        name of the service
     * @param staticWorkload StaticWorkload object
     * @return WorkloadOptions
     */
    public StaticWorkload putStaticWorkload(String domain, String service, StaticWorkload staticWorkload, String resourceOwner) {
        try {
            return client.putStaticWorkload(domain, service, staticWorkload, resourceOwner);
        } catch (ClientResourceException ex) {
            throw new MSDClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new MSDClientException(ClientResourceException.BAD_REQUEST, ex.getMessage());
        }
    }

    /**
     * Api to perform a static workload Delete operation for a domain, service and name
     *
     * @param domain  name of the domain
     * @param service name of the service
     * @param name name of the static workload
     */
    public void deleteStaticWorkload(String domain, String service, String name, String resourceOwner) {
        try {
            client.deleteStaticWorkload(domain, service, name, resourceOwner);
        } catch (ClientResourceException ex) {
            throw new MSDClientException(ex.getCode(), ex.getData());
        } catch (Exception ex) {
            throw new MSDClientException(ClientResourceException.BAD_REQUEST, ex.getMessage());
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
