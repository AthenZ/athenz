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
package com.yahoo.athenz.zts.cert.impl;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import com.yahoo.athenz.auth.util.Crypto;
import org.testng.Assert;
import org.testng.annotations.Test;

public class KeyStoreCertSignerTest {

    @Test
    public void testGenerateX509Certificate() {
        // 
        try (KeyStoreCertSigner keyStoreCertSigner = new KeyStoreCertSigner(CA_CERT, CA_KEY, 43200)) {
            String certPem = keyStoreCertSigner.generateX509Certificate("sys.auth.zts", null, CLIENT_CSR_PEM, null, 0);
            X509Certificate cert = Crypto.loadX509Certificate(certPem);
            long certExpiry = Duration.between(cert.getNotBefore().toInstant(), cert.getNotAfter().toInstant()).toMinutes();
            // assertion
            Assert.assertEquals(cert.getIssuerX500Principal().getName(), "CN=Sample Self Signed Intermediate CA,O=Athenz,C=US");
            Assert.assertEquals(cert.getSubjectX500Principal().getName(), "CN=sys.auth.zts,O=Athenz,C=US");
            Assert.assertEquals(certExpiry, 43200);
        }
    }

    @Test
    public void testGenerateX509CertificateWithExpiry() {
        int certExpiryMins = 60;
        try (KeyStoreCertSigner keyStoreCertSigner = new KeyStoreCertSigner(CA_CERT, CA_KEY, 43200)) {
            String certPem = keyStoreCertSigner.generateX509Certificate("sys.auth.zts", null, CLIENT_CSR_PEM, null, certExpiryMins);
            X509Certificate cert = Crypto.loadX509Certificate(certPem);
            long certExpiry = Duration.between(cert.getNotBefore().toInstant(), cert.getNotAfter().toInstant()).toMinutes();
            // assertion
            Assert.assertEquals(cert.getIssuerX500Principal().getName(), "CN=Sample Self Signed Intermediate CA,O=Athenz,C=US");
            Assert.assertEquals(cert.getSubjectX500Principal().getName(), "CN=sys.auth.zts,O=Athenz,C=US");
            Assert.assertEquals(certExpiry, 60);
        }
    }

    @Test
    public void testGetCACertificate() {
        try (KeyStoreCertSigner keyStoreCertSigner = new KeyStoreCertSigner(CA_CERT, CA_KEY, 43200)) {
            // assertion
            Assert.assertEquals(keyStoreCertSigner.getCACertificate("sys.auth.zts"), CA_CERT_PEM);
        }
    }

    @Test
    public void testGetMaxCertExpiryTimeMins() {
        try (KeyStoreCertSigner keyStoreCertSigner = new KeyStoreCertSigner(CA_CERT, CA_KEY, 43200)) {
            // assertion
            Assert.assertEquals(keyStoreCertSigner.getMaxCertExpiryTimeMins(), 43200);
        }
    }

    private static final String CLIENT_CSR_PEM = "-----BEGIN CERTIFICATE REQUEST-----\nMIIEtDCCApwCAQAwNTELMAkGA1UEBhMCVVMxDzANBgNVBAoMBkF0aGVuejEVMBMG\nA1UEAwwMc3lzLmF1dGguenRzMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKC\nAgEA3FEBV0u6Jt2Rc/jNCnlOXRnNbkzy5PKrEASWJCPmaXmQ+VaCmcoZQpeWI8Nq\nEV2XOgyT8KUCnNEBpwPjBgVOipwafaCthF7AjiTSdbMZgRsrnMtYs5WXZe1mkkUi\n9Kz6fJUXxycZb+RUJ8u0q33Lke/j7jYBUKf+zbTxrvaqdcMrlaKSNi6d+Vok5pba\nUdwCQJKqgZOePby+ljOTYgZe4J+VCEiLfjBh2iCNSnOFVkhRzC+rXwq/HvqN2Nh6\nSQ4isWz+fDVeWBSm83KV9wEbXm2yBPkLOSnjyNvmHZpMkifVNu+2+wbhh0czuqbo\n/q42w7hE932R9gC3if0/LoLn3IlzN39JKSicMYgCKQgu/watxHgu5Gjp4Nnkopn0\nPDkThwWfIAumpQwP8shmfA/E6stQpmZItwdMcKo0YKbobzMEG5J0agoXNeoeFDkF\n9CvfNTDOkwT5zI+lvGg8wIm/vGV8BjHWgjtD1S0ttp7zGVuplNjm5iLRsRZTf39T\nHa9jrOeHoi4l8wDqolRIY+vu4c97KmFTfEZIoH892AKbc+poKuF6m0k8WCwqLbKN\nw4+adE6gqcPGUxxLVo5QJTetOwOjVk50SpbFMdBgR0SUvh7pq1POP1m9rh7lcPRM\nuYb/Hn/VHGfTpoyg5UHili83+srsMShPi//vxRmMElRQDuUCAwEAAaA6MDgGCSqG\nSIb3DQEJDjErMCkwJwYDVR0RBCAwHoIJbG9jYWxob3N0ggtOb3QgRGVmaW5lZIcE\nfwAAATANBgkqhkiG9w0BAQsFAAOCAgEAiexG/Vn58piospz7tZy7rR5vqs8goaYF\nCDtkdX/2fvq/2lwatS7SJvJK1iqeLu2NVI1eRBqjuM2QOR1fGPRMyBcFAHP0CfIz\nMuUIFn99Wn+83hA1EhBd0svKszFqH8QjYLMjUCRsUQFh46RSxlxCVJEiBsm/2jo3\nQn2irxz5l06MCM8IuB2GwMYoeB+//rAA797P5drInKOr4PT5gvDfL1vYWuT89MEd\nUmgW5IOdMbeR2kA46CqQM6+/+TlJ9sszPO5ZELIhlbbu6E1OuFvMjqfofxtYPy59\n20921+IcCNKMzYeDgTie34gOSvmB6x9E8U4qz+X4donM/52R5zhC2L1dBA5YYb+H\nWOUUCFjoztomFJsiWZ9EaGcChtTZdx1ShMQ4f//YkE5ejy2FT3hObMwTxkk4P5Sc\nC8cBxvZist80g0vjG6qbhMutx4e08D8m1iwCHDIxiA3hJa5IBsyRkbiJoc8YDCD4\nWP1M/FPS6Tj3h/OiR8qu/ABviX/qSUeuqRaDWUE+uKr79ijFtdLRSpZWGuNZprRy\nAl5ZGnTa2nGVfZgG2M3Kv3JVQRC+1TpcAIAykGXM22B6quQSHhVfDmfjQlCCYOMY\ntRaQWV/c9KIyTrj+/vQiK6VJy/p8PtVX7DibxNK861XSuj4zNItfzfn0mZOWsHXK\nXa9cpmaoiag=\n-----END CERTIFICATE REQUEST-----\n";
    private static final String CA_CERT_PEM = "-----BEGIN CERTIFICATE-----\nMIIFdjCCA16gAwIBAgIJANazM2+IRxRWMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV\nBAYTAlVTMQ8wDQYDVQQKDAZBdGhlbnoxJTAjBgNVBAMMHFNhbXBsZSBTZWxmIFNp\nZ25lZCBBdGhlbnogQ0EwHhcNMTkxMTI3MDY1MTI4WhcNMjkxMTI0MDY1MTI4WjBL\nMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQXRoZW56MSswKQYDVQQDDCJTYW1wbGUg\nU2VsZiBTaWduZWQgSW50ZXJtZWRpYXRlIENBMIICIjANBgkqhkiG9w0BAQEFAAOC\nAg8AMIICCgKCAgEAxUMo9hldK/NnJ66/MmHZCVVR97A11clKqB1yGGEsUmhSVcrZ\ng4fmaO/8q4ybQBct0FJCzo3Es8IUwTFexodY2JA48FUMDNSuubAgxmVNePt1fAVx\nVGZQsxjmkngvWo0XNWGK6o8Rej8B0hUjYwAsnrkMLQp6twGxBhBkG92We5reaPoz\nvzLf5LzkjB76ugIKxHlCseQPpXcf1jomOyGvOwnhz8tYF9sMRoRcnN8SDhhrvMaf\nmzsJOLRyHlbk39/q5ApONZh/77Vsqi/ziWHPyuVE3INHDmNd7CKeck2figHh3MdW\nNFZHWfxnon2zCb89B2nh5Zwst6QPH1J+2im3QXQW+Jhiih1lOoEtn43y0FEvhIhW\nJO0xIbpUd0baIFKngvqXwzWG8JczrlJ8f6+MnPcfCZzwTB8QZybVLKgAEQqac6cn\nzo4uM0dW3djppaPpMrzIpjQNB7dNIPcd3mQlA1eLOtIQQR4Q4zqSiikuMghplFgM\nd0txvFm/U2qlWA1kUrrMuzdIc/YeghLYGOM5HaZ6iTpLjDsJ3KJPKMNHAZVwrnnt\nXzr61dP136YEXtCLAd2A8cDI1wS7coi29y7aTOe4SmfnBQzcr5Irg89ZeBCosT33\nDVfBqnu0Ogp+4H9EzvNpxCQcBSFV2jWOTlSqsmMuHeRwtUhCYK+AMzMbyQcCAwEA\nAaNjMGEwHQYDVR0OBBYEFC8OWWsK8o0oe6DQ1CCZgQ6p1L0RMB8GA1UdIwQYMBaA\nFMjGXlwtqxHqSP5jqM/9xYm4z+BSMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/\nBAQDAgEGMA0GCSqGSIb3DQEBCwUAA4ICAQAkY2rB7js411iHbsE/MeWR0fvqPx/V\ndGEn+ygVPFs6574LdEBN9VeuPULoWMJ+huuXvjwhWpXHzqzjfG2IIHYrHdHqD5YK\njFQdEx/qJQJAGrR3OCClenCFpsfPQ/15t5GGDhT5S6PueNVMRV8k6OGxY49moXul\nU+7U7J9K6gw7I0iSLlfwCwEl0Cw4tY0eLf2DGVEx72FNrq/Fw5bJedwOdK1O3zQp\nY+s9F+YoPh/CKTkedNUCPuyA2wM/c1zwFMltHSwkK1GHtY3lmLYeHN5Kk4SZJ6dl\nml8ZQQCtDyqLYxS1UI7bIbY/kSzUchPXVwBTuZCzGxlebq5cWEVVZSZza7SFIKPx\nDPVa8HzB/FdJ1GMW6rDC4nx8c3UfPyCdsBkrnelrryQbodDW9vDFyrs/WjTHyVO/\nxTC4k186CvDo5jylGZJD4lK/lqWalFkh+hAJdER5U+aAJnVG5vRX8yrIL7UDC0WS\nYqvZOpLeyCMcL1D1nnuPmRKDoLgeIQR4lKYT5AR04HhyBIgqJ2lWAQ5/EbWnreJ1\n0zceQWhfLoCGi/RWu5e3/LDEUP6/wVFTmlwNWmxghFoIK8xKAvznSzsi6N/bv2f+\nMIUOCFdGnWIX0OlhlbDHxUcSkt9SohebOcOBfilD/SY8Q+9+xu/8ucfHAQ7+/7lt\n6ZZ+7BMBBCKyjg==\n-----END CERTIFICATE-----\n";
    private static final String CA_KEY_PEM = "-----BEGIN RSA PRIVATE KEY-----\nMIIJJwIBAAKCAgEAxUMo9hldK/NnJ66/MmHZCVVR97A11clKqB1yGGEsUmhSVcrZ\ng4fmaO/8q4ybQBct0FJCzo3Es8IUwTFexodY2JA48FUMDNSuubAgxmVNePt1fAVx\nVGZQsxjmkngvWo0XNWGK6o8Rej8B0hUjYwAsnrkMLQp6twGxBhBkG92We5reaPoz\nvzLf5LzkjB76ugIKxHlCseQPpXcf1jomOyGvOwnhz8tYF9sMRoRcnN8SDhhrvMaf\nmzsJOLRyHlbk39/q5ApONZh/77Vsqi/ziWHPyuVE3INHDmNd7CKeck2figHh3MdW\nNFZHWfxnon2zCb89B2nh5Zwst6QPH1J+2im3QXQW+Jhiih1lOoEtn43y0FEvhIhW\nJO0xIbpUd0baIFKngvqXwzWG8JczrlJ8f6+MnPcfCZzwTB8QZybVLKgAEQqac6cn\nzo4uM0dW3djppaPpMrzIpjQNB7dNIPcd3mQlA1eLOtIQQR4Q4zqSiikuMghplFgM\nd0txvFm/U2qlWA1kUrrMuzdIc/YeghLYGOM5HaZ6iTpLjDsJ3KJPKMNHAZVwrnnt\nXzr61dP136YEXtCLAd2A8cDI1wS7coi29y7aTOe4SmfnBQzcr5Irg89ZeBCosT33\nDVfBqnu0Ogp+4H9EzvNpxCQcBSFV2jWOTlSqsmMuHeRwtUhCYK+AMzMbyQcCAwEA\nAQKCAgApZIZb3canSlQDB7AnKlEYnEau6tLhIXQBAuzGIN3kDO/6AK7T4th+fJ1Q\nghixwiti42ARZ7422irwvyNcFVqXVuwbwjzdFGP1ove9qdQv5tQoShwV0cJtUnRP\nl9iX77NHCEjWH19Tf5UqODVMuOSkCcB8Uw6dCEXVN+tJzZ2eIkk5Tgc9v7crkFeE\n75s9HOCVibxtB6Yg2nZbxafwEIlsog44RDsgBl71DSFB6a0oOAejfSpQsHqm43Zu\n11z/fUUUxPTUWkO+URuUOqun0FaCBMoGW6W1ZzR2MG1/HrqzguGaKln0cYZXY5d7\niVTgXri3rYgxXiwj/NEPiYgEz2wceRVQAKHCMrgVH4hfv7umpo8vMY7Yh4mGWVRq\nbkFs9y/Z05naQlLhgHQVC8YKwkexfdf4EXmQ5Z4mAV7S1SBELE455MFamzlorLWv\n9A2SgGd+MZh0jOj/WS8oFtnUbds5ylexCFEfI7B/MM4HyL5RC3TW24AqrWwxEFpK\nnkAED0i1ezJ8chMklzxk+4fM//z3VEepZuEglDdCBm6I781oMi1d7n3NYTphobcY\ngBpUvOLiVkFghILzbgye+6zsRTkYvue98gzCQCLvBVD7mJe2abXQiyMz9SfuB29o\nqzXB5xFit4BC7wScvi21wFZi9fNNascGUyj6m+cD11kci6JPQQKCAQEA+u1trwvD\nXdiJERQcuvvTSkEVINpUh1DdPiUAk1uc3JHCqtuDx+9Vf6YLsUbVlTX8EJr5lSpH\ndHunWxQjTawTi32ooil3ArJCipBjKXfHeh6+3Fxas6T4AkwAelwfZcm8LPF6jKL4\nOuuZRzLtI646Nv8LNDroSBy3MBSzBYzPvUVHvV7ZsJ+/8TV/cWsyuPrJiz2QNdWA\n+jtJbN6xm7x1GYrM82EECKRJen9/iUk6hHROnNvJ2b69imSJ9FJR1G+1UZ9zGpuH\nDXU8dkCHPxuJhjZBhdlUKqo+2jISaOrwGtfZrnVQ/GJYuscmOO1p2UtvCrwKB5IG\nZW/b4T5OOQSErQKCAQEAyUACiRn2eCwxhP7d9qSp4u6gPMdtsQtYiWNeOljsvS5O\nBcz3ka9cx6BMG5FHqIPUxZOW7a5xsZkmQ7JdH5gsUooi+lwG5FEgbZQOYqVsIBLb\nD4ISg0gcxZAR7g1WmpWDhpufzj9tIpgONT/hsrvNV3ypTRaxdZPk6R67VwxHGO5B\nkoCm6f+zFNOiuZxlWZCMFBvOTa89o4vj0cyDGWydeBJCGvSuBC0YHNY9ucr8jJRo\nBljH4s4VllYR+ZavcKewTsDivFd5lncaMmfEiezvjonGhigqM96fBXvl6DJynFwY\nslvB8wPEeWzS/9Ppdu/OLZ8uVJ4XfRPAjfqi6lOHAwKCAQA3MSgR+4ViS/GCFylm\nm2NTDtOl4T/8b3XqaFsjDmCHR2xJBnWK8YKdzBkASjNKWZBy2pOREraa0WPzLY/C\nUtoNsXr5CCPMLQdj0PRut5DhtIeIkqvEncGLR8pHH6IsUl4YiJjK/EGbPBz/wxzT\n30ugsyJ0v4w96EsGwVbLHrjGyclIxucc6VZfqMO6X7jNZSQVg1oH7UksQQQadTUd\nqysajiQcWDd56yDaV9bmjHvZjHeKGvHf+gtYuFp7qeujzVpVdLvtm03uUN4WqITX\nBaiPI7nvxei0ZbPjbGYOO7bKQLX5oIZKrRsVIh6vINFKYUQwWUHffmf3wc3cUkcE\nVZEVAoIBAHkfwWbq7WCemJ9HFiigKm+e12o9TVPFVGA8IjZT1wh1mhf7qPVR6jFr\n1OKyqcJOtfzEO46J83vEhTcxXsLpP6Pd5/du8+buvOm2toHAtjcHojjPPH0vJcHy\nWBhChuE7I5IckC3+Fp0/jy2VaS29wnTpXqw7AEuX26pDCNX3WcMzgtu9+rfTYeEj\nD0lPS+CAEw73PU+cLSkFxPQ8dpsSuCPQOWEn6qQwz9ZrS3NLLH0fxQws2wEyr+Nv\nohnqC2VuR7redJiOvWtF+8pikfPBWt0bJxUPj3bwgh022MTLuBdLhsGyYCT3G4VJ\nbiTzUgx3gEwNBkF/dPueq8HIG82UwCkCggEAT265jH++M+9dArjXUAbrXzaQu03q\njZ1ViGFtfknFMdWdMZShztnfNwFuZ4ClkUvdYOtCfdk5t/ISsZMYv9FfaVYADdfo\nvRrlxmgIgrvDdEyg0o2rtw9ZshkdAIEfKAu+h5s3CL2kLwLaELbVfPo3hoeBRvuu\n1f3UJ4+hK1aAiE1fWsx0e4nvDelewk22RC4H9UmcA7+S9VXiGWS9II7VQ4ILASeO\nkwQvq1ds/HjXGqID/sYxGS/oCHEgv3FD5/MD0ff7w2VBc419e9VAAevdw0gGFOkh\nqYKWWny54XhfVUx2iBibaoFu74IXRhcMsHHGmLMFzTY4/Q4DQyNRyDIPTg==\n-----END RSA PRIVATE KEY-----\n";
    private static final X509Certificate CA_CERT = Crypto.loadX509Certificate(CA_CERT_PEM);
    private static final PrivateKey CA_KEY = Crypto.loadPrivateKey(CA_KEY_PEM);
}
