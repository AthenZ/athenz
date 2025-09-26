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
package io.athenz.server.gcp.common.store.impl;

import com.google.api.gax.paging.Page;
import com.google.cloud.storage.Blob;
import com.google.cloud.storage.Storage;
import com.yahoo.athenz.zms.DomainData;
import com.yahoo.athenz.zms.JWSDomain;
import com.yahoo.athenz.zms.SignedDomain;
import com.yahoo.athenz.zms.SignedDomains;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.io.IOException;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;

import static org.mockito.Mockito.*;
import static org.testng.Assert.*;

public class GcsChangeLogStoreTest {

    private Storage storage;
    private GcsChangeLogStore store;

    @BeforeMethod
    public void setUp() {
        storage = mock(Storage.class);
        store = Mockito.spy(new GcsChangeLogStore("test-project", "test-bucket"));
        store.storage = storage; // inject mock
    }


    @Test
    public void testGetLocalSignedDomain_CacheHit() {
        SignedDomain domain = new SignedDomain();
        store.tempSignedDomainMap.put("test", domain);
        SignedDomain result = store.getLocalSignedDomain("test");
        assertEquals(result, domain);
        assertFalse(store.tempSignedDomainMap.containsKey("test"));
    }

    @Test
    public void testGetLocalSignedDomain_CacheMiss() {
        SignedDomain domain = new SignedDomain();
        doReturn(domain).when(store).getSignedDomain("test");
        SignedDomain result = store.getLocalSignedDomain("test");
        assertEquals(result, domain);
    }

    @Test
    public void testGetLocalJWSDomain_CacheHit() {
        JWSDomain domain = new JWSDomain();
        store.tempJWSDomainMap.put("test", domain);
        JWSDomain result = store.getLocalJWSDomain("test");
        assertEquals(result, domain);
        assertFalse(store.tempJWSDomainMap.containsKey("test"));
    }

    @Test
    public void testGetLocalJWSDomain_CacheMiss() {
        JWSDomain domain = new JWSDomain();
        doReturn(domain).when(store).getJWSDomain("test");
        JWSDomain result = store.getLocalJWSDomain("test");
        assertEquals(result, domain);
    }

    @Test
    public void testGetSignedDomain_Success() {
        // Arrange
        String domainName = "test-domain";
        String jsonContent = "{\"domain\":{\"name\":\"test-domain\"}}";
        byte[] domainBytes = jsonContent.getBytes();

        when(storage.readAllBytes(eq("test-bucket"), eq(domainName))).thenReturn(domainBytes);

        // Act
        SignedDomain result = store.getSignedDomain(domainName);

        // Assert
        assertNotNull(result);
        assertEquals("test-domain", result.getDomain().getName());
        verify(storage).readAllBytes("test-bucket", domainName);
    }

    @Test
    public void testGetSignedDomain_StorageException() {
        // Arrange
        String domainName = "test-domain";
        when(storage.readAllBytes(eq("test-bucket"), eq(domainName)))
                .thenThrow(new RuntimeException("Storage error"));

        // Act
        SignedDomain result = store.getSignedDomain(domainName);

        // Assert
        assertNull(result);
        verify(storage).readAllBytes("test-bucket", domainName);
    }

    @Test
    public void testGetSignedDomain_DeserializationException() {
        // Arrange
        String domainName = "test-domain";
        byte[] invalidJson = "{invalid-json}".getBytes();
        when(storage.readAllBytes(eq("test-bucket"), eq(domainName))).thenReturn(invalidJson);

        // Act
        SignedDomain result = store.getSignedDomain(domainName);

        // Assert
        assertNull(result);
        verify(storage).readAllBytes("test-bucket", domainName);
    }

    @Test
    public void testGetJWSDomain_Success() {
        // Arrange
        String domainName = "test-domain";
        String jsonContent = "{\"payload\":\"{\\\"domain\\\":{\\\"name\\\":\\\"test-domain\\\"}}\"}";
        byte[] domainBytes = jsonContent.getBytes();

        when(storage.readAllBytes(eq("test-bucket"), eq(domainName))).thenReturn(domainBytes);

        // Act
        JWSDomain result = store.getJWSDomain(domainName);

        // Assert
        assertNotNull(result);
        assertEquals("{\"domain\":{\"name\":\"test-domain\"}}", result.getPayload());
        verify(storage).readAllBytes("test-bucket", domainName);
    }

    @Test
    public void testGetJWSDomain_StorageException() {
        // Arrange
        String domainName = "test-domain";
        when(storage.readAllBytes(eq("test-bucket"), eq(domainName)))
                .thenThrow(new RuntimeException("Storage error"));

        // Act
        JWSDomain result = store.getJWSDomain(domainName);

        // Assert
        assertNull(result);
        verify(storage).readAllBytes("test-bucket", domainName);
    }

    @Test
    public void testGetJWSDomain_DeserializationException() {
        // Arrange
        String domainName = "test-domain";
        byte[] invalidJson = "{invalid-json}".getBytes();
        when(storage.readAllBytes(eq("test-bucket"), eq(domainName))).thenReturn(invalidJson);

        // Act
        JWSDomain result = store.getJWSDomain(domainName);

        // Assert
        assertNull(result);
        verify(storage).readAllBytes("test-bucket", domainName);
    }


    @Test
    public void testListObjects() {
        Blob blob1 = mock(Blob.class);
        when(blob1.getName()).thenReturn(".hidden");
        Blob blob2 = mock(Blob.class);
        when(blob2.getName()).thenReturn("domain1");
        when(blob2.getUpdateTime()).thenReturn(System.currentTimeMillis());
        Iterable<Blob> blobs = Arrays.asList(blob1, blob2);
        com.google.api.gax.paging.Page<Blob> page = mock(com.google.api.gax.paging.Page.class);
        when(page.iterateAll()).thenReturn(blobs);
        when(storage.list(anyString())).thenReturn(page);

        List<String> domains = new ArrayList<>();
        store.listObjects(domains, 0);
        assertTrue(domains.contains("domain1"));
        assertFalse(domains.contains(".hidden"));
    }

    @Test
    public void testListObjects_FiltersDotFilesAndModTime() {
        long currentTime = System.currentTimeMillis();
        long olderTime = currentTime - 1000;
        long modTime = currentTime - 500;  // Time between olderTime and currentTime

        // Hidden file that should be filtered by name
        Blob hiddenBlob = mock(Blob.class);
        when(hiddenBlob.getName()).thenReturn(".hidden");

        // Domain with newer timestamp that should be included
        Blob newerDomainBlob = mock(Blob.class);
        when(newerDomainBlob.getName()).thenReturn("domain1");
        when(newerDomainBlob.getUpdateTime()).thenReturn(currentTime);

        // Domain with older timestamp that should be filtered by modTime
        Blob olderDomainBlob = mock(Blob.class);
        when(olderDomainBlob.getName()).thenReturn("domain2");
        when(olderDomainBlob.getUpdateTime()).thenReturn(olderTime);

        Iterable<Blob> blobs = Arrays.asList(hiddenBlob, newerDomainBlob, olderDomainBlob);
        Page<Blob> page = mock(Page.class);
        when(page.iterateAll()).thenReturn(blobs);
        when(storage.list(anyString())).thenReturn(page);

        List<String> domains = new ArrayList<>();
        store.listObjects(domains, modTime);

        // Verify results
        assertEquals(domains.size(), 1);
        assertTrue(domains.contains("domain1"));
        assertFalse(domains.contains(".hidden"));
        assertFalse(domains.contains("domain2"));
    }

    @Test
    public void testSetLastModificationTimestamp() {
        // Test valid timestamp
        store.setLastModificationTimestamp("12345");
        assertEquals(store.lastModTime, 12345L);

        // Test null value
        store.setLastModificationTimestamp(null);
        assertEquals(store.lastModTime, 0L);

        // Test empty string
        store.setLastModificationTimestamp("");
        assertEquals(store.lastModTime, 0L);

        // Test blank string (whitespace only)
        store.setLastModificationTimestamp("   ");
        assertEquals(store.lastModTime, 0L);

        // Test invalid format (NumberFormatException)
        store.setLastModificationTimestamp("abc");
        assertEquals(store.lastModTime, 0L);

        // Test another invalid format
        store.setLastModificationTimestamp("123abc");
        assertEquals(store.lastModTime, 0L);
    }

    @Test
    public void testSupportsFullRefresh() {
        assertFalse(store.supportsFullRefresh());
    }

    @Test
    public void testRemoveLocalDomainAndSaveLocalDomain_NoOp() {
        store.removeLocalDomain("test");
        store.saveLocalDomain("test", new SignedDomain());
        store.saveLocalDomain("test", new JWSDomain());
        // No exception means pass
    }

    @Test
    public void testGetServerDomainList() {
        // Setup mock storage behavior
        Blob blob1 = mock(Blob.class);
        when(blob1.getName()).thenReturn("domain1");
        Blob blob2 = mock(Blob.class);
        when(blob2.getName()).thenReturn("domain2");
        Iterable<Blob> blobs = List.of(blob1, blob2);
        Page<Blob> page = mock(Page.class);
        when(page.iterateAll()).thenReturn(blobs);
        when(storage.list(anyString())).thenReturn(page);

        Set<String> result = store.getServerDomainList();

        assertEquals(result.size(), 2);
        assertTrue(result.contains("domain1"));
        assertTrue(result.contains("domain2"));
    }

    @Test
    public void testGetUpdatedDomainList() {
        // Setup initial lastModTime
        long initialModTime = System.currentTimeMillis() - 10000;
        store.lastModTime = initialModTime;

        // Setup mock blob with timestamp after lastModTime
        Blob blob = mock(Blob.class);
        when(blob.getName()).thenReturn("updated-domain");
        when(blob.getUpdateTime()).thenReturn(System.currentTimeMillis());

        // Setup mock storage
        Iterable<Blob> blobs = List.of(blob);
        Page<Blob> page = mock(Page.class);
        when(page.iterateAll()).thenReturn(blobs);
        when(storage.list(anyString())).thenReturn(page);

        StringBuilder lastModTimeBuffer = new StringBuilder();
        List<String> domains = store.getUpdatedDomainList(lastModTimeBuffer);

        assertEquals(domains.size(), 1);
        assertEquals(domains.get(0), "updated-domain");
        assertNotEquals(lastModTimeBuffer.toString(), String.valueOf(initialModTime));
    }

    @Test
    public void testGetUpdatedSignedDomains() {
        // Mock behavior for getUpdatedDomainList
        List<String> mockDomains = List.of("domain1", "domain2");
        StringBuilder lastModTimeBuffer = new StringBuilder();

        doReturn(mockDomains).when(store).getUpdatedDomainList(any(StringBuilder.class));

        // Setup mock for getSignedDomain
        SignedDomain domain1 = new SignedDomain().setDomain(new DomainData().setName("domain1"));
        SignedDomain domain2 = new SignedDomain().setDomain(new DomainData().setName("domain2"));

        doReturn(domain1).when(store).getSignedDomain("domain1");
        doReturn(domain2).when(store).getSignedDomain("domain2");

        SignedDomains result = store.getUpdatedSignedDomains(lastModTimeBuffer);

        assertNotNull(result);
        List<SignedDomain> domains = result.getDomains();
        assertEquals(domains.size(), 2);
        assertEquals(domains.get(0).getDomain().getName(), "domain1");
        assertEquals(domains.get(1).getDomain().getName(), "domain2");
    }

    @Test
    public void testGetUpdatedSignedDomains_WithNullDomain() {
        // Mock behavior for getUpdatedDomainList
        List<String> mockDomains = List.of("domain1", "domain2");
        StringBuilder lastModTimeBuffer = new StringBuilder();

        doReturn(mockDomains).when(store).getUpdatedDomainList(any(StringBuilder.class));

        // Setup mock for getSignedDomain - domain2 returns null
        SignedDomain domain1 = new SignedDomain().setDomain(new DomainData().setName("domain1"));

        doReturn(domain1).when(store).getSignedDomain("domain1");
        doReturn(null).when(store).getSignedDomain("domain2");

        SignedDomains result = store.getUpdatedSignedDomains(lastModTimeBuffer);

        assertNotNull(result);
        List<SignedDomain> domains = result.getDomains();
        assertEquals(domains.size(), 1); // Only one domain is added since the other is null
        assertEquals(domains.get(0).getDomain().getName(), "domain1");
    }


    @Test
    public void testGetUpdatedJWSDomains() throws IOException {
        // Mock behavior for getUpdatedDomainList
        List<String> mockDomains = List.of("domain1");
        StringBuilder lastModTimeBuffer = new StringBuilder();

        doReturn(mockDomains).when(store).getUpdatedDomainList(any(StringBuilder.class));

        // Setup mock for getJWSDomain
        JWSDomain domain1 = new JWSDomain().setPayload("{\"domain\":{\"name\":\"test-domain\"}}");


        doReturn(domain1).when(store).getJWSDomain("domain1");

        List<JWSDomain> result = store.getUpdatedJWSDomains(lastModTimeBuffer);

        assertNotNull(result);
        assertEquals(result.size(), 1);
        assertTrue(result.get(0).getPayload().contains("test-domain"));
    }

    @Test
    public void testGetLocalDomainList() {
        // Setup - ensure lastModTime is 0
        store.lastModTime = 0;

        // Mock listObjects to add some domains
        doAnswer(invocation -> {
            List<String> domains = invocation.getArgument(0);
            domains.add("domain3");
            domains.add("domain4");
            return null;
        }).when(store).listObjects(anyList(), eq(0L));

        // Mock getAllDomains to add additional domains
        doAnswer(invocation -> {
            List<String> domains = invocation.getArgument(0);
            // These domains should be added to the ones from listObjects
            domains.add("domain1");
            domains.add("domain2");
            return true;
        }).when(store).getAllDomains(anyList());

        // Call the method
        List<String> result = store.getLocalDomainList();

        // Verify results
        assertNotNull(result);
        assertEquals(4, result.size());
        assertTrue(result.contains("domain1"));
        assertTrue(result.contains("domain2"));
        assertTrue(result.contains("domain3"));
        assertTrue(result.contains("domain4"));

        // Verify that lastModTime was initialized to a non-zero value
        assertNotEquals(0, store.lastModTime);
        assertTrue(store.lastModTime > 0);

        // Verify maps were cleared
        assertTrue(store.tempSignedDomainMap.isEmpty());
        assertTrue(store.tempJWSDomainMap.isEmpty());

        // Verify methods were called
        verify(store).listObjects(anyList(), eq(0L));
        verify(store).getAllDomains(anyList());
    }

    @Test
    public void testGetAllDomains_Success() throws Exception {
        // Create test data
        List<String> domains = List.of("domain1", "domain2");

        // Mock executor service
        ExecutorService mockExecutor = mock(ExecutorService.class);
        when(mockExecutor.awaitTermination(anyLong(), any())).thenReturn(true);

        // Create spy and mock getExecutorService
        doReturn(mockExecutor).when(store).getExecutorService();

        boolean result = store.getAllDomains(domains);

        assertTrue(result);
        verify(mockExecutor).shutdown();
        verify(mockExecutor).awaitTermination(anyLong(), eq(TimeUnit.SECONDS));
        // Verify threads were created for each domain
        ArgumentCaptor<Runnable> runnableCaptor = ArgumentCaptor.forClass(Runnable.class);
        verify(mockExecutor, times(2)).execute(runnableCaptor.capture());
    }

    @Test
    public void testGetAllDomains_InterruptedException() throws Exception {
        // Create test data
        List<String> domains = new ArrayList<>();
        domains.add("domain1");

        // Mock executor service with interruption
        ExecutorService mockExecutor = mock(ExecutorService.class);
        when(mockExecutor.awaitTermination(anyLong(), any())).thenThrow(new InterruptedException("Test interruption"));

        // Create spy and mock getExecutorService
        doReturn(mockExecutor).when(store).getExecutorService();

        boolean result = store.getAllDomains(domains);

        assertFalse(result);
        verify(mockExecutor).shutdown();
        verify(mockExecutor).shutdownNow();
        assertTrue(store.tempSignedDomainMap.isEmpty());
        assertTrue(store.tempJWSDomainMap.isEmpty());
    }

    @Test
    public void testGetExecutorService() {
        ExecutorService service = store.getExecutorService();
        assertNotNull(service);
        service.shutdown();
    }

    @Test
    public void testSetJWSDomainSupport() {
        assertFalse(store.jwsDomainSupport);
        store.setJWSDomainSupport(true);
        assertTrue(store.jwsDomainSupport);
    }

    @Test
    public void testObjectGcsThread_SaveSignedDomain() {
        // Create test objects
        SignedDomain testDomain = new SignedDomain().setDomain(new DomainData().setName("test-domain"));

        // Create spy and mock getSignedDomain
        doReturn(testDomain).when(store).getSignedDomain("domain1");

        // Create and run thread
        GcsChangeLogStore.ObjectGcsThread thread = store.new ObjectGcsThread(
                "domain1",
                store.tempSignedDomainMap,
                store.tempJWSDomainMap,
                storage,
                false
        );

        thread.run();

        // Verify domain was saved to map
        assertEquals(store.tempSignedDomainMap.size(), 1);
        assertSame(store.tempSignedDomainMap.get("domain1"), testDomain);
    }

    @Test
    public void testObjectGcsThread_SaveJWSDomain() {
        // Create test objects
        JWSDomain testDomain = new JWSDomain().setPayload("{\"domain\":{\"name\":\"test-domain\"}}");

        doReturn(testDomain).when(store).getJWSDomain("domain1");

        // Create and run thread
        GcsChangeLogStore.ObjectGcsThread thread = store.new ObjectGcsThread(
                "domain1",
                store.tempSignedDomainMap,
                store.tempJWSDomainMap,
                storage,
                true
        );

        thread.run();

        // Verify domain was saved to map
        assertEquals(store.tempJWSDomainMap.size(), 1);
        assertSame(store.tempJWSDomainMap.get("domain1"), testDomain);
    }

    @Test
    public void testObjectGcsThread_SaveSignedDomain_ExceptionHandling() {
        doThrow(new RuntimeException("Test exception")).when(store).getSignedDomain("domain1");

        // Create and run thread
        GcsChangeLogStore.ObjectGcsThread thread = store.new ObjectGcsThread(
                "domain1",
                store.tempSignedDomainMap,
                store.tempJWSDomainMap,
                storage,
                false
        );

        // Should not throw exception
        thread.run();

        // Map should be empty
        assertTrue(store.tempSignedDomainMap.isEmpty());
    }

    @Test
    public void testObjectGcsThread_SaveJWSDomain_ExceptionHandling() {
        // Mock getJWSDomain to throw an exception
        doThrow(new RuntimeException("Test exception")).when(store).getJWSDomain("domain1");

        // Create and run thread with jwsSupport=true to trigger saveJWSDomain
        GcsChangeLogStore.ObjectGcsThread thread = store.new ObjectGcsThread(
                "domain1",
                store.tempSignedDomainMap,
                store.tempJWSDomainMap,
                storage,
                true
        );

        // Should not throw exception
        thread.run();

        // Verify map remains empty since getJWSDomain threw an exception
        assertTrue(store.tempJWSDomainMap.isEmpty());
    }

    @Test
    public void testServerDomainAndJWSDomainMethodsReturnNull() {
        assertNull(store.getServerDomainModifiedList());
        assertNull(store.getServerSignedDomain("any-domain"));
        assertNull(store.getServerJWSDomain("any-domain"));
    }
}
