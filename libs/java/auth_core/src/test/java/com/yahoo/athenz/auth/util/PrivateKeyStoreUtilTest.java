package com.yahoo.athenz.auth.util;

import static org.testng.Assert.*;
import org.testng.annotations.Test;
import org.mockito.Mockito;

import com.yahoo.athenz.auth.ServerPrivateKey;
import java.util.function.Function;

public class PrivateKeyStoreUtilTest {

    @Test
    public void testGetPrivateKeyFromCloudParameterNullRegion() {
        ServerPrivateKey privateKey = PrivateKeyStoreUtil.getPrivateKeyFromCloudParameter(
                "zms", null, "rsa", param -> "value");
        assertNull(privateKey);

        privateKey = PrivateKeyStoreUtil.getPrivateKeyFromCloudParameter(
                "zms", "", "rsa", param -> "value");
        assertNull(privateKey);
    }

    @Test
    public void testGetPrivateKeyFromCloudParameterUnknownService() {
        ServerPrivateKey privateKey = PrivateKeyStoreUtil.getPrivateKeyFromCloudParameter(
                "unknown", "us-west-2", "rsa", param -> "value");
        assertNull(privateKey);
    }

    @Test
    public void testGetPrivateKeyFromCloudParameterZmsService() {
        // Mock the function to return valid private key data
        Function<String, String> mockFn = param -> {
            if (param.contains("key_id")) {
                return "test-key-id";
            } else {
                // Return a valid PEM that Crypto can parse
                return Crypto.ybase64DecodeString("LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JSUV2UUlCQURBTkJna3Foa2lHOXcwQkFRRUZBQVNDQktjd2dnU2pBZ0VBQW9JQkFRQ3VWYlUxRFdRWENqYnAKbFZCYzNTb3M3QmFCcTdJbStlZ3JUM1ZvZGY1Y0pEYVl1QTRlZ1FzcTg5bVJlSUgzWjFNd1NiVmdrbDdVUWQvUgpIbkJDUEdJbCtlY3NEM2x2UXVXdS9FV3ZrWnFSOHFaR1JPbmdQNitqVy9XWVBNdXJ5YTFxSWdweVVMSDRIeU13ClZGZG9hSjFwMWRwVGxFaVFaRjQvK3g3TUxZUkVMcnhyRkQvd2FBSi9lZk9CNkVWWGdtOGl1ZGlnWTFRUWpnNE4KUHZPVHdaTlhJRWxMbDZnNW03SmRNbjBtOUtiQWJYRFFiSmdXZUxqMitEV2lIZVVKblM5VWZXQVJmaVpnaTRpcQo3UEhJVUMxUmwyVXNWYVZjYmF6eWxMTkNGZjh0b1BpVXhNem9IMmtSYkRMNlRQdnNhQlEvZ3JHeFA1SlZCT2wwCkcrSk5nRXBsQWdNQkFBRUNnZ0VBS3RXNndHbm9kdUZrOW5vYWpScjBRYVZHRlNkUTV4M2hyMmFNYmE0Qi95MnkKQlA1K3JCUlg5R3N0Slg1NkRiV3hBdHpCOVgxMWcwVWpON3JiOFJzZkc0ZmNlVXpkNGZBS1Z4VUVkODJYblVrdgpmRHhVOGdqcXhiMVZkdkZOZjBXYXptN3VBYVN6MXZ0bm94MjFSZjlLVE5TUXRucHZ2YTZrWEJCc3N0N0FCNkhUCnd4OGc4U2tVcnU2V1ZhdGxWWUY2MGltRTZyVWJUbjhDR2pDL1lFUDRNbzhPTU96MnhXOEhDM3JnTlRqNnVVWm8KWEVoTkZDN25zRmd0cGl3WEhmbG9GajlQZWxTYXNlaWdjSThFTmlyOGdrUVZ2SDJ4M3VRK1VHbW9XVEpST2FJbgpQYnVWbjM5TG9jODI2MzQvYzFIbXBnQWlBODRzU3FUOVJyb05haXN2MlFLQmdRRGJYVk1BanltaTB6K0hXS01KClNGZGJITmVQeDIxczJVLzA5MzkyRDd3MlN3WFdkWEZTRkxQS09kN1k3ZGtPcGQrNUJpbXozOTRkWVdxY1ZkdUsKbUlqbVJ5SU9WaFg3bnhreEcyL1ZRR0c0U0JETnkvdnVjNllMUGc5S09VUEVIeW5McEl6VTc1U0RQdk5PcFlPVQpzNVpBcDFrMnBLQ3ZrdUE0OStBNmF4TXl3d0tCZ1FETHJ6b2lBOWsyMUhKQ2xtaWdxN2V5VDc3VzY0RXFpNERoCmRWRUw3VEFWVWRwcDFXWkVLd1BhMVFjUlYvSk5wV3pkZlhJZjh2N1VpQVNYVzlUTHRHdmF6UUE2dlc2eVJNc3cKa0VnTmpSYWNQZ2Vjc2ZSbHBxQ0hUV1hVS0ZCK3pKaW5DbWtBVHQrYWtWbTJFMUhoYWIxUkFzcG44Sm9lOUtWSApCRmhxMkJ6ZVZ3S0JnQXVDRm9FQnhZcjk2b2ZJbGFQOGpnV0ZnekFMNEtpMGJ6ZXNhY1hLT3JrOXY1d0hMcU1hCjc5NHFzK3VwVUxWejI5UVMzQU1JeHNuWURwbGZYamJVNGk3bFhxM3RWbS9hS3dzNG9qOXlxMnlsRjJJK1d6MXEKMkYvZGpqWnRaVy8xOHk4b1MvaFdidlVEdmRXeXZhR1N0SjhVa0RrQmE5am5uWENTYnIvL0dKdTVBb0dCQUlkVwpmeVRBZlhnY2lyTFFaN2FZbkdwQW9RRlRZS1lqODk1RVVYcDl4UG5rZlNycHJ1SStJakN4bjJvMmZwWUQ3ZEtmCkk1amVTSW15RE5wLzZrUzV5MzRQY1ZNZjlrbFl0YUNEalJqeTRmWjFBOGxyU05pVWJ6QXNmdmQ3RlFNNXpJQVkKWGFNbVJMQVZZanVNaEMrTFJkY1RScVdCZ0M2V05GWTJUcmlXOUVYREFvR0FkRzlHamVKeVNRVFpXTTR6V3REMAo5TmYwOStUWGZQK24xM3QvOUdHTWtPdFFNdFllSnZhNXdXNEtFR1Q1ZGxpQzEvRk9iZkJqQ0JWV3owS3Rxdmc4CjdjUTY2N2x2d3Y2OUd4citGRVNORDhBVGsxY1lTOENqQzJEbHpCZDZFdGlDYzRtR0l5ZFB1MTA2QVl1RGtxRHkKNFFRZ0tPZlZzSGhVNXFESFpMV2thK1E9Ci0tLS0tRU5EIFBSSVZBVEUgS0VZLS0tLS0K");
            }
        };

        System.setProperty("athenz.aws.zms.key_name", "custom_key_name");
        System.setProperty("athenz.aws.zms.key_id_name", "custom_key_id");

        ServerPrivateKey privateKey = PrivateKeyStoreUtil.getPrivateKeyFromCloudParameter(
                "zms", "us-west-2", "rsa", mockFn);
        assertNotNull(privateKey);
        assertEquals(privateKey.getId(), "test-key-id");

        System.clearProperty("athenz.aws.zms.key_name");
        System.clearProperty("athenz.aws.zms.key_id_name");
    }

    @Test
    public void testGetPrivateKeyFromCloudParameterZtsService() {
        // Similar test for ZTS service
        Function<String, String> mockFn = Mockito.mock(Function.class);
        Mockito.when(mockFn.apply("service_private_key.rsa")).thenReturn(
                Crypto.ybase64DecodeString("LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JSUV2UUlCQURBTkJna3Foa2lHOXcwQkFRRUZBQVNDQktjd2dnU2pBZ0VBQW9JQkFRQ3VWYlUxRFdRWENqYnAKbFZCYzNTb3M3QmFCcTdJbStlZ3JUM1ZvZGY1Y0pEYVl1QTRlZ1FzcTg5bVJlSUgzWjFNd1NiVmdrbDdVUWQvUgpIbkJDUEdJbCtlY3NEM2x2UXVXdS9FV3ZrWnFSOHFaR1JPbmdQNitqVy9XWVBNdXJ5YTFxSWdweVVMSDRIeU13ClZGZG9hSjFwMWRwVGxFaVFaRjQvK3g3TUxZUkVMcnhyRkQvd2FBSi9lZk9CNkVWWGdtOGl1ZGlnWTFRUWpnNE4KUHZPVHdaTlhJRWxMbDZnNW03SmRNbjBtOUtiQWJYRFFiSmdXZUxqMitEV2lIZVVKblM5VWZXQVJmaVpnaTRpcQo3UEhJVUMxUmwyVXNWYVZjYmF6eWxMTkNGZjh0b1BpVXhNem9IMmtSYkRMNlRQdnNhQlEvZ3JHeFA1SlZCT2wwCkcrSk5nRXBsQWdNQkFBRUNnZ0VBS3RXNndHbm9kdUZrOW5vYWpScjBRYVZHRlNkUTV4M2hyMmFNYmE0Qi95MnkKQlA1K3JCUlg5R3N0Slg1NkRiV3hBdHpCOVgxMWcwVWpON3JiOFJzZkc0ZmNlVXpkNGZBS1Z4VUVkODJYblVrdgpmRHhVOGdqcXhiMVZkdkZOZjBXYXptN3VBYVN6MXZ0bm94MjFSZjlLVE5TUXRucHZ2YTZrWEJCc3N0N0FCNkhUCnd4OGc4U2tVcnU2V1ZhdGxWWUY2MGltRTZyVWJUbjhDR2pDL1lFUDRNbzhPTU96MnhXOEhDM3JnTlRqNnVVWm8KWEVoTkZDN25zRmd0cGl3WEhmbG9GajlQZWxTYXNlaWdjSThFTmlyOGdrUVZ2SDJ4M3VRK1VHbW9XVEpST2FJbgpQYnVWbjM5TG9jODI2MzQvYzFIbXBnQWlBODRzU3FUOVJyb05haXN2MlFLQmdRRGJYVk1BanltaTB6K0hXS01KClNGZGJITmVQeDIxczJVLzA5MzkyRDd3MlN3WFdkWEZTRkxQS09kN1k3ZGtPcGQrNUJpbXozOTRkWVdxY1ZkdUsKbUlqbVJ5SU9WaFg3bnhreEcyL1ZRR0c0U0JETnkvdnVjNllMUGc5S09VUEVIeW5McEl6VTc1U0RQdk5PcFlPVQpzNVpBcDFrMnBLQ3ZrdUE0OStBNmF4TXl3d0tCZ1FETHJ6b2lBOWsyMUhKQ2xtaWdxN2V5VDc3VzY0RXFpNERoCmRWRUw3VEFWVWRwcDFXWkVLd1BhMVFjUlYvSk5wV3pkZlhJZjh2N1VpQVNYVzlUTHRHdmF6UUE2dlc2eVJNc3cKa0VnTmpSYWNQZ2Vjc2ZSbHBxQ0hUV1hVS0ZCK3pKaW5DbWtBVHQrYWtWbTJFMUhoYWIxUkFzcG44Sm9lOUtWSApCRmhxMkJ6ZVZ3S0JnQXVDRm9FQnhZcjk2b2ZJbGFQOGpnV0ZnekFMNEtpMGJ6ZXNhY1hLT3JrOXY1d0hMcU1hCjc5NHFzK3VwVUxWejI5UVMzQU1JeHNuWURwbGZYamJVNGk3bFhxM3RWbS9hS3dzNG9qOXlxMnlsRjJJK1d6MXEKMkYvZGpqWnRaVy8xOHk4b1MvaFdidlVEdmRXeXZhR1N0SjhVa0RrQmE5am5uWENTYnIvL0dKdTVBb0dCQUlkVwpmeVRBZlhnY2lyTFFaN2FZbkdwQW9RRlRZS1lqODk1RVVYcDl4UG5rZlNycHJ1SStJakN4bjJvMmZwWUQ3ZEtmCkk1amVTSW15RE5wLzZrUzV5MzRQY1ZNZjlrbFl0YUNEalJqeTRmWjFBOGxyU05pVWJ6QXNmdmQ3RlFNNXpJQVkKWGFNbVJMQVZZanVNaEMrTFJkY1RScVdCZ0M2V05GWTJUcmlXOUVYREFvR0FkRzlHamVKeVNRVFpXTTR6V3REMAo5TmYwOStUWGZQK24xM3QvOUdHTWtPdFFNdFllSnZhNXdXNEtFR1Q1ZGxpQzEvRk9iZkJqQ0JWV3owS3Rxdmc4CjdjUTY2N2x2d3Y2OUd4citGRVNORDhBVGsxY1lTOENqQzJEbHpCZDZFdGlDYzRtR0l5ZFB1MTA2QVl1RGtxRHkKNFFRZ0tPZlZzSGhVNXFESFpMV2thK1E9Ci0tLS0tRU5EIFBSSVZBVEUgS0VZLS0tLS0K"));
        Mockito.when(mockFn.apply("service_private_key_id.rsa")).thenReturn("zts-key-id");

        ServerPrivateKey privateKey = PrivateKeyStoreUtil.getPrivateKeyFromCloudParameter(
                "zts", "us-west-2", "rsa", mockFn);
        assertNotNull(privateKey);
        assertEquals(privateKey.getId(), "zts-key-id");
    }

    @Test
    public void testGetPrivateKeyFromCloudParameterZtsServiceException() {
        Function<String, String> mockFn = Mockito.mock(Function.class);
        Mockito.when(mockFn.apply("service_private_key.rsa")).thenThrow(new RuntimeException("getParameter failure"));

        ServerPrivateKey privateKey = PrivateKeyStoreUtil.getPrivateKeyFromCloudParameter(
                "zts", "us-west-2", "rsa", mockFn);
        assertNull(privateKey);
    }

    @Test
    public void testGetPrivateKeyFromCloudParameterMsdService() {
        // Similar test for MSD service
        Function<String, String> mockFn = param -> {
            if (param.contains("key_id")) {
                return "msd-key-id";
            } else {
                return Crypto.ybase64DecodeString("LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JSUV2UUlCQURBTkJna3Foa2lHOXcwQkFRRUZBQVNDQktjd2dnU2pBZ0VBQW9JQkFRQ3VWYlUxRFdRWENqYnAKbFZCYzNTb3M3QmFCcTdJbStlZ3JUM1ZvZGY1Y0pEYVl1QTRlZ1FzcTg5bVJlSUgzWjFNd1NiVmdrbDdVUWQvUgpIbkJDUEdJbCtlY3NEM2x2UXVXdS9FV3ZrWnFSOHFaR1JPbmdQNitqVy9XWVBNdXJ5YTFxSWdweVVMSDRIeU13ClZGZG9hSjFwMWRwVGxFaVFaRjQvK3g3TUxZUkVMcnhyRkQvd2FBSi9lZk9CNkVWWGdtOGl1ZGlnWTFRUWpnNE4KUHZPVHdaTlhJRWxMbDZnNW03SmRNbjBtOUtiQWJYRFFiSmdXZUxqMitEV2lIZVVKblM5VWZXQVJmaVpnaTRpcQo3UEhJVUMxUmwyVXNWYVZjYmF6eWxMTkNGZjh0b1BpVXhNem9IMmtSYkRMNlRQdnNhQlEvZ3JHeFA1SlZCT2wwCkcrSk5nRXBsQWdNQkFBRUNnZ0VBS3RXNndHbm9kdUZrOW5vYWpScjBRYVZHRlNkUTV4M2hyMmFNYmE0Qi95MnkKQlA1K3JCUlg5R3N0Slg1NkRiV3hBdHpCOVgxMWcwVWpON3JiOFJzZkc0ZmNlVXpkNGZBS1Z4VUVkODJYblVrdgpmRHhVOGdqcXhiMVZkdkZOZjBXYXptN3VBYVN6MXZ0bm94MjFSZjlLVE5TUXRucHZ2YTZrWEJCc3N0N0FCNkhUCnd4OGc4U2tVcnU2V1ZhdGxWWUY2MGltRTZyVWJUbjhDR2pDL1lFUDRNbzhPTU96MnhXOEhDM3JnTlRqNnVVWm8KWEVoTkZDN25zRmd0cGl3WEhmbG9GajlQZWxTYXNlaWdjSThFTmlyOGdrUVZ2SDJ4M3VRK1VHbW9XVEpST2FJbgpQYnVWbjM5TG9jODI2MzQvYzFIbXBnQWlBODRzU3FUOVJyb05haXN2MlFLQmdRRGJYVk1BanltaTB6K0hXS01KClNGZGJITmVQeDIxczJVLzA5MzkyRDd3MlN3WFdkWEZTRkxQS09kN1k3ZGtPcGQrNUJpbXozOTRkWVdxY1ZkdUsKbUlqbVJ5SU9WaFg3bnhreEcyL1ZRR0c0U0JETnkvdnVjNllMUGc5S09VUEVIeW5McEl6VTc1U0RQdk5PcFlPVQpzNVpBcDFrMnBLQ3ZrdUE0OStBNmF4TXl3d0tCZ1FETHJ6b2lBOWsyMUhKQ2xtaWdxN2V5VDc3VzY0RXFpNERoCmRWRUw3VEFWVWRwcDFXWkVLd1BhMVFjUlYvSk5wV3pkZlhJZjh2N1VpQVNYVzlUTHRHdmF6UUE2dlc2eVJNc3cKa0VnTmpSYWNQZ2Vjc2ZSbHBxQ0hUV1hVS0ZCK3pKaW5DbWtBVHQrYWtWbTJFMUhoYWIxUkFzcG44Sm9lOUtWSApCRmhxMkJ6ZVZ3S0JnQXVDRm9FQnhZcjk2b2ZJbGFQOGpnV0ZnekFMNEtpMGJ6ZXNhY1hLT3JrOXY1d0hMcU1hCjc5NHFzK3VwVUxWejI5UVMzQU1JeHNuWURwbGZYamJVNGk3bFhxM3RWbS9hS3dzNG9qOXlxMnlsRjJJK1d6MXEKMkYvZGpqWnRaVy8xOHk4b1MvaFdidlVEdmRXeXZhR1N0SjhVa0RrQmE5am5uWENTYnIvL0dKdTVBb0dCQUlkVwpmeVRBZlhnY2lyTFFaN2FZbkdwQW9RRlRZS1lqODk1RVVYcDl4UG5rZlNycHJ1SStJakN4bjJvMmZwWUQ3ZEtmCkk1amVTSW15RE5wLzZrUzV5MzRQY1ZNZjlrbFl0YUNEalJqeTRmWjFBOGxyU05pVWJ6QXNmdmQ3RlFNNXpJQVkKWGFNbVJMQVZZanVNaEMrTFJkY1RScVdCZ0M2V05GWTJUcmlXOUVYREFvR0FkRzlHamVKeVNRVFpXTTR6V3REMAo5TmYwOStUWGZQK24xM3QvOUdHTWtPdFFNdFllSnZhNXdXNEtFR1Q1ZGxpQzEvRk9iZkJqQ0JWV3owS3Rxdmc4CjdjUTY2N2x2d3Y2OUd4citGRVNORDhBVGsxY1lTOENqQzJEbHpCZDZFdGlDYzRtR0l5ZFB1MTA2QVl1RGtxRHkKNFFRZ0tPZlZzSGhVNXFESFpMV2thK1E9Ci0tLS0tRU5EIFBSSVZBVEUgS0VZLS0tLS0K");
            }
        };

        ServerPrivateKey privateKey = PrivateKeyStoreUtil.getPrivateKeyFromCloudParameter(
                "msd", "us-west-2", "rsa", mockFn);
        assertNotNull(privateKey);
        assertEquals(privateKey.getId(), "msd-key-id");
    }

    @Test
    public void testGetPrivateKeyFromCloudParameterFailedToLoad() {
        // Test case when loading private key fails
        Function<String, String> mockFn = param -> "invalid-key-data";

        ServerPrivateKey privateKey = PrivateKeyStoreUtil.getPrivateKeyFromCloudParameter(
                "zms", "us-west-2", "rsa", mockFn);
        assertNull(privateKey);
    }
}