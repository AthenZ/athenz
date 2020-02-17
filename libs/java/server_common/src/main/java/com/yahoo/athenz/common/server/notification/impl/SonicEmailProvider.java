package com.yahoo.athenz.common.server.notification.impl;

import com.yahoo.athenz.common.server.notification.EmailProvider;

import java.util.Collection;

public class SonicEmailProvider implements EmailProvider {
    @Override
    public boolean sendEmail(String subject, String body, boolean status, Collection<String> recipients, String from, byte[] logoImage) {
        throw new UnsupportedOperationException("Sonic Email Provider not implemented");
    }
}
