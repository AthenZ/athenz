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

import static org.testng.Assert.*;

import java.security.KeyStore;
import javax.net.ssl.SSLContext;

import org.apache.http.ssl.SSLContextBuilder;
import org.testng.annotations.Test;

public class MSDClientTest {

  @Test
  public void testMSDUrlLookUpFromEnv() throws Exception {
    System.setProperty("athenz.msd.client.msd_url", "https://localhost:4443/msd/v1");
    MSDRDLClientMock msdrdlClientMock = new MSDRDLClientMock();
    MSDClient msdClient = new MSDClient(null, createDummySslContext());
    msdClient.client = msdrdlClientMock;
    TransportPolicyRules tprList = msdClient.getTransportPolicyRules(null, null);
    assertNotNull(tprList);
    System.clearProperty("athenz.msd.client.msd_url");
    msdClient.close();
  }

  @Test
  public void testConstructorArguments() throws Exception {
    try {
      new MSDClient(null, createDummySslContext());
      fail();
    } catch (IllegalArgumentException ex) {
      assertTrue(ex.getMessage().contains("MSD URL must be specified"));
    }

    try {
      new MSDClient("https://localhost:4443/msd/v1", null);
      fail();
    } catch (IllegalArgumentException ex) {
      assertTrue(ex.getMessage().contains("SSLContext object must be specified"));
    }
  }

  @Test
  public void testTransportPolicyRules() throws Exception {
    MSDRDLClientMock msdrdlClientMock = new MSDRDLClientMock();
    MSDClient msdClient = new MSDClient("https://localhost:4443/msd/v1", createDummySslContext());
    msdClient.client = msdrdlClientMock;
    TransportPolicyRules tprList = msdClient.getTransportPolicyRules(null, null);
    assertNotNull(tprList);
    assertEquals(tprList.getIngress().size(), 1);
    assertEquals(tprList.getEgress().size(), 1);
    msdClient.close();
  }

  @Test
  public void testTransportPolicyRulesException() throws Exception {
    MSDRDLClientMock msdrdlClientMock = new MSDRDLClientMock();
    MSDClient msdClient = new MSDClient("https://localhost:4443/msd/v1", createDummySslContext());
    msdClient.client = msdrdlClientMock;
    try {
      msdClient.getTransportPolicyRules("throw-ex", null);
    } catch (ResourceException re) {
      assertEquals(re.getCode(), 400);
    }
    msdClient.close();
  }


  @Test
  public void testGetWorkloadsByIP() throws Exception {
    MSDRDLClientMock msdrdlClientMock = new MSDRDLClientMock();
    MSDClient msdClient = new MSDClient("https://localhost:4443/msd/v1", createDummySslContext());
    msdClient.client = msdrdlClientMock;
    Workloads workloads = msdClient.getWorkloadsByIP("10.0.0.1", null, null);
    assertNotNull(workloads);
    assertEquals(workloads.getWorkloadList().get(0).getProvider(), "openstack");
    assertEquals(workloads.getWorkloadList().get(0).getUuid(), "avve-resw");
    assertEquals(workloads.getWorkloadList().get(0).getDomainName(), "athenz");
    assertEquals(workloads.getWorkloadList().get(0).getServiceName(), "api");
    assertNotNull(workloads.getWorkloadList().get(0).getUpdateTime());
    assertNull(workloads.getWorkloadList().get(0).getIpAddresses());
    try {
      msdClient.getWorkloadsByIP("127.0.0.1", null, null);
      fail();
    } catch (ResourceException re) {
      assertEquals(re.getCode(), 404);
    }
    try {
      msdClient.getWorkloadsByIP("bad-req", null, null);
      fail();
    } catch (Exception ex) {
      assertTrue(ex.getMessage().contains("bad request"));
    }
    msdClient.close();
  }

  @Test
  public void testGetWorkloadsByService() throws Exception {
    MSDRDLClientMock msdrdlClientMock = new MSDRDLClientMock();
    MSDClient msdClient = new MSDClient("https://localhost:4443/msd/v1", createDummySslContext());
    msdClient.client = msdrdlClientMock;
    Workloads workloads = msdClient.getWorkloadsByService("athenz", "api", null, null);
    assertNotNull(workloads);
    assertEquals(workloads.getWorkloadList().get(0).getProvider(), "openstack");
    assertEquals(workloads.getWorkloadList().get(0).getUuid(), "avve-resw");
    assertNull(workloads.getWorkloadList().get(0).getDomainName());
    assertNull(workloads.getWorkloadList().get(0).getServiceName());
    assertNotNull(workloads.getWorkloadList().get(0).getUpdateTime());
    assertTrue(workloads.getWorkloadList().get(0).getIpAddresses().contains("10.0.0.1"));
    try {
      msdClient.getWorkloadsByService("bad-domain", "api", null, null);
      fail();
    } catch (ResourceException re) {
      assertEquals(re.getCode(), 404);
    }
    try {
      msdClient.getWorkloadsByService("bad-req", "api", null, null);
      fail();
    } catch (Exception ex) {
      assertTrue(ex.getMessage().contains("bad request"));
    }
    msdClient.close();
  }

  private SSLContext createDummySslContext() throws Exception {
    return SSLContextBuilder.create()
        .setProtocol(null)
        .setSecureRandom(null)
        .loadTrustMaterial((KeyStore) null, null)
        .loadKeyMaterial((KeyStore) null, null, null)
        .build();
  }
}