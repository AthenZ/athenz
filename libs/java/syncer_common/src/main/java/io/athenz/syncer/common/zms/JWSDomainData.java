package io.athenz.syncer.common.zms;

import com.yahoo.athenz.zms.JWSDomain;

public class JWSDomainData {
    final JWSDomain jwsDomain;
    final long fetchTime;

    public JWSDomainData(JWSDomain jwsDomain, long fetchTime) {
        this.jwsDomain = jwsDomain;
        this.fetchTime = fetchTime;
    }

    public JWSDomain getJwsDomain() {
        return jwsDomain;
    }

    public long getFetchTime() {
        return fetchTime;
    }
}
