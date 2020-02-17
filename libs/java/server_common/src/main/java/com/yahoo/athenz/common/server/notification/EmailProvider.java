package com.yahoo.athenz.common.server.notification;

import java.util.Collection;

public interface EmailProvider {
    boolean sendEmail(String subject, String body, boolean status, Collection<String> recipients, String from, byte[] logoImage);
}
