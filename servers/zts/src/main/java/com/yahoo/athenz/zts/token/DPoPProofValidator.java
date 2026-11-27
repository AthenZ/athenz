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
package com.yahoo.athenz.zts.token;

import com.nimbusds.jose.JWSAlgorithm;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.token.DPoPProof;
import com.yahoo.athenz.auth.token.DPoPProofException;
import com.yahoo.athenz.auth.token.DPoPProofOptions;
import com.yahoo.athenz.zts.ZTSConsts;
import jakarta.servlet.http.HttpServletRequest;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.function.Function;

/**
 * ZTS policy for validating DPoP proofs (RFC 9449) presented to the
 * oauth2 token endpoint. The proof htu must be one of the allowed token
 * endpoint urls derived from the configured issuers and, unless disabled,
 * its host must also match the host the request was sent to (or the issuer
 * mapped to that host) so a proof created for one allowed url is not
 * accepted through another.
 */
public class DPoPProofValidator {

    private static final Logger LOGGER = LoggerFactory.getLogger(DPoPProofValidator.class);

    private static final String TOKEN_ENDPOINT_PATH = "/oauth2/token";
    private static final String HEADER_HOST = "Host";

    private final DPoPProofOptions options;
    private final boolean requireCertKeyMatch;
    private final boolean htuMatchRequestHost;
    private final Function<HttpServletRequest, String> hostMappedIssuer;
    private final List<String> supportedAlgorithms;

    /**
     * Create the validator based on the athenz.zts.dpop_* system properties.
     *
     * @param oauth2Issuers set of configured oauth2 issuers
     * @throws IllegalArgumentException if the configuration is not valid
     */
    public DPoPProofValidator(Set<String> oauth2Issuers) {
        this(oauth2Issuers, request -> null);
    }

    /**
     * Create the validator based on the athenz.zts.dpop_* system properties.
     *
     * @param oauth2Issuers set of configured oauth2 issuers
     * @param hostMappedIssuer returns the issuer mapped to the request host, if any.
     *          When the request host is mapped to an issuer (e.g. requests from an
     *          external gateway), proofs for that issuer's token endpoint are accepted.
     * @throws IllegalArgumentException if the configuration is not valid
     */
    public DPoPProofValidator(Set<String> oauth2Issuers, Function<HttpServletRequest, String> hostMappedIssuer) {

        this.hostMappedIssuer = hostMappedIssuer;

        DPoPProofOptions.Builder builder = DPoPProofOptions.builder()
                .maxAgeSecs(Long.parseLong(System.getProperty(ZTSConsts.ZTS_PROP_DPOP_PROOF_MAX_AGE,
                        Long.toString(DPoPProofOptions.DEFAULT_MAX_AGE_SECS))))
                .clockSkewSecs(Long.parseLong(System.getProperty(ZTSConsts.ZTS_PROP_DPOP_PROOF_CLOCK_SKEW,
                        Long.toString(DPoPProofOptions.DEFAULT_CLOCK_SKEW_SECS))))
                .maxProofSize(Integer.parseInt(System.getProperty(ZTSConsts.ZTS_PROP_DPOP_MAX_PROOF_SIZE,
                        Integer.toString(DPoPProofOptions.DEFAULT_MAX_PROOF_SIZE))))
                .minRsaKeySize(Integer.parseInt(System.getProperty(ZTSConsts.ZTS_PROP_DPOP_MIN_RSA_KEY_SIZE,
                        Integer.toString(DPoPProofOptions.DEFAULT_MIN_RSA_KEY_SIZE))));

        final String algNames = System.getProperty(ZTSConsts.ZTS_PROP_DPOP_SIGNING_ALGORITHMS);
        if (!StringUtil.isEmpty(algNames)) {
            List<JWSAlgorithm> algorithms = new ArrayList<>();
            for (String name : algNames.split(",")) {
                final String trimmed = name.trim();
                if (!trimmed.isEmpty()) {
                    algorithms.add(JWSAlgorithm.parse(trimmed));
                }
            }
            builder.allowedAlgorithms(algorithms);
        }

        if (oauth2Issuers != null) {
            for (String issuer : oauth2Issuers) {
                addIssuerHtu(builder, issuer);
            }
        }

        final String allowedHtus = System.getProperty(ZTSConsts.ZTS_PROP_DPOP_ALLOWED_HTU);
        if (!StringUtil.isEmpty(allowedHtus)) {
            for (String htu : allowedHtus.split(",")) {
                final String trimmed = htu.trim();
                if (!trimmed.isEmpty()) {
                    builder.addAllowedHtu(trimmed);
                }
            }
        }

        options = builder.build();
        requireCertKeyMatch = Boolean.parseBoolean(
                System.getProperty(ZTSConsts.ZTS_PROP_DPOP_REQUIRE_CERT_KEY_MATCH, "false"));
        htuMatchRequestHost = Boolean.parseBoolean(
                System.getProperty(ZTSConsts.ZTS_PROP_DPOP_HTU_MATCH_REQUEST_HOST, "true"));

        List<String> algorithms = new ArrayList<>();
        for (JWSAlgorithm alg : options.getAllowedAlgorithms()) {
            algorithms.add(alg.getName());
        }
        supportedAlgorithms = Collections.unmodifiableList(algorithms);

        LOGGER.info("DPoP proof validation enabled: algorithms={}, htu={}, htuMatchRequestHost={}, maxAge={}, "
                + "clockSkew={}, certKeyMatch={}", supportedAlgorithms, options.getAllowedHtus(), htuMatchRequestHost,
                options.getMaxAgeSecs(), options.getClockSkewSecs(), requireCertKeyMatch);
    }

    private static void addIssuerHtu(DPoPProofOptions.Builder builder, final String issuer) {
        if (StringUtil.isEmpty(issuer)) {
            return;
        }
        final String htu = issuer + TOKEN_ENDPOINT_PATH;
        if (DPoPProof.normalizeHtu(htu) == null) {
            LOGGER.warn("Skipping issuer {} for DPoP htu validation: not an absolute http(s) uri", issuer);
            return;
        }
        builder.addAllowedHtu(htu);
    }

    /**
     * Validate the DPoP proof included in the request, if any.
     *
     * @param request http servlet request
     * @param principal authenticated principal
     * @return the RFC 7638 thumbprint of the proof key, or null when no DPoP header is present
     * @throws DPoPProofException if the proof is not valid
     */
    public String validate(HttpServletRequest request, Principal principal) {

        final Enumeration<String> headers = request.getHeaders(DPoPProof.HTTP_HEADER);
        if (headers == null || !headers.hasMoreElements()) {
            return null;
        }
        final String proof = headers.nextElement();
        if (headers.hasMoreElements()) {
            throw new DPoPProofException("multiple DPoP headers");
        }

        DPoPProof dpopProof = new DPoPProof(proof, request.getMethod(), options, System.currentTimeMillis() / 1000);
        final String jkt = dpopProof.getJwkThumbprint();

        if (htuMatchRequestHost && !isRequestHtuHost(request, URI.create(dpopProof.getHtu()).getHost())) {
            throw new DPoPProofException("htu does not match request host");
        }

        if (requireCertKeyMatch && principal != null) {
            X509Certificate cert = principal.getX509Certificate();
            if (cert != null && !jkt.equals(DPoPProof.computeJwkThumbprint(cert.getPublicKey()))) {
                throw new DPoPProofException("proof key does not match certificate key");
            }
        }

        LOGGER.debug("validated DPoP proof: principal={}, jti={}, jkt={}",
                principal == null ? null : principal.getFullName(), dpopProof.getJwtId(), jkt);
        return jkt;
    }

    /**
     * The htu host must be the host the request was sent to or, if the request
     * host is mapped to an issuer, the host of that issuer's token endpoint.
     */
    boolean isRequestHtuHost(HttpServletRequest request, final String htuHost) {

        if (htuHost.equalsIgnoreCase(getRequestHost(request))) {
            return true;
        }
        final String mappedIssuer = hostMappedIssuer.apply(request);
        if (StringUtil.isEmpty(mappedIssuer)) {
            return false;
        }
        try {
            return htuHost.equalsIgnoreCase(new URI(mappedIssuer).getHost());
        } catch (URISyntaxException ex) {
            return false;
        }
    }

    /**
     * Same host resolution as the issuer host mapping: the Host header, or the
     * server name when the header is not present, without the port.
     *
     * @param request http servlet request
     * @return lower case request host (ipv6 addresses in brackets) or null if not available
     */
    static String getRequestHost(HttpServletRequest request) {

        String host = request.getHeader(HEADER_HOST);
        if (StringUtil.isEmpty(host)) {
            host = request.getServerName();
        }
        if (StringUtil.isEmpty(host)) {
            return null;
        }
        final int portIdx = host.startsWith("[") ? host.indexOf("]:") + 1 : host.indexOf(':');
        if (portIdx > 0) {
            host = host.substring(0, portIdx);
        }
        return host.toLowerCase(Locale.ROOT);
    }

    /**
     * @return names of the JWS algorithms accepted for DPoP proofs
     */
    public List<String> getSupportedAlgorithms() {
        return supportedAlgorithms;
    }

    DPoPProofOptions getOptions() {
        return options;
    }

    boolean isRequireCertKeyMatch() {
        return requireCertKeyMatch;
    }

    boolean isHtuMatchRequestHost() {
        return htuMatchRequestHost;
    }
}
