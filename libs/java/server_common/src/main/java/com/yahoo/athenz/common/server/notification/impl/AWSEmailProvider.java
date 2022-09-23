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

package com.yahoo.athenz.common.server.notification.impl;

import com.amazonaws.regions.Region;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.simpleemail.AmazonSimpleEmailService;
import com.amazonaws.services.simpleemail.AmazonSimpleEmailServiceClientBuilder;
import com.amazonaws.services.simpleemail.model.RawMessage;
import com.amazonaws.services.simpleemail.model.SendRawEmailRequest;
import com.amazonaws.services.simpleemail.model.SendRawEmailResult;
import com.yahoo.athenz.common.server.notification.EmailProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.mail.internet.MimeMessage;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.util.Collection;

public class AWSEmailProvider implements EmailProvider {
    private static final Logger LOGGER = LoggerFactory.getLogger(AWSEmailProvider.class);
    private final AmazonSimpleEmailService ses;

    @Override
    public boolean sendEmail(Collection<String> recipients, String from, MimeMessage mimeMessage) {
        try {
            try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
                mimeMessage.writeTo(outputStream);
                RawMessage rawMessage = new RawMessage(ByteBuffer.wrap(outputStream.toByteArray()));
                SendRawEmailRequest rawEmailRequest = new SendRawEmailRequest(rawMessage);
                SendRawEmailResult result = ses.sendRawEmail(rawEmailRequest);
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug("Email with messageId={} sent successfully.", result.getMessageId());
                }
                return result != null;
            }
        } catch (Exception ex) {
            LOGGER.error("The email could not be sent. Error message: {}", ex.getMessage());
            return false;
        }
    }

    public AWSEmailProvider() {
        this(initSES());
    }

    AWSEmailProvider(AmazonSimpleEmailService ses) {
        this.ses = ses;
    }

    private static AmazonSimpleEmailService initSES() {
        Region region = Regions.getCurrentRegion();
        if (region == null) {
            region = Region.getRegion(Regions.US_EAST_1);
        }
        return AmazonSimpleEmailServiceClientBuilder.standard().withRegion(region.getName()).build();
    }
}
