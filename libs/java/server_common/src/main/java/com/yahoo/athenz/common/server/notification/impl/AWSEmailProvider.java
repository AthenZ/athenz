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

import com.yahoo.athenz.common.server.util.Utils;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sesv2.SesV2Client;
import software.amazon.awssdk.services.sesv2.model.*;
import com.yahoo.athenz.common.server.notification.EmailProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.mail.internet.MimeMessage;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.util.Collection;

public class AWSEmailProvider implements EmailProvider {
    private static final Logger LOGGER = LoggerFactory.getLogger(AWSEmailProvider.class);
    private final SesV2Client ses;

    @Override
    public boolean sendEmail(Collection<String> recipients, String from, MimeMessage mimeMessage) {

        try {
            try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
                mimeMessage.writeTo(outputStream);

                SendEmailRequest emailRequest = SendEmailRequest.builder()
                        .fromEmailAddress(from)
                        .destination(Destination.builder()
                                .toAddresses(recipients)
                                .build())
                        .content(EmailContent.builder()
                                .raw(RawMessage.builder()
                                        .data(SdkBytes.fromByteBuffer(ByteBuffer.wrap(outputStream.toByteArray())))
                                        .build())
                                .build())
                        .build();

                SendEmailResponse result = ses.sendEmail(emailRequest);

                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug("Email with messageId={} sent successfully.", result.messageId());
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

    AWSEmailProvider(SesV2Client ses) {
        this.ses = ses;
    }

    private static SesV2Client initSES() {
        Region region = Utils.getAwsRegion(Region.US_EAST_1);
        return SesV2Client.builder().region(region).build();
    }
}
