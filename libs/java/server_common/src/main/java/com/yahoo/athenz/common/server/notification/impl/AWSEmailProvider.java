/*
 * Copyright 2020 Verizon Media
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

import javax.mail.Session;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.util.Collection;
import java.util.Properties;

import static com.yahoo.athenz.common.server.notification.NotificationServiceConstants.CHARSET_UTF_8;
import static com.yahoo.athenz.common.server.notification.NotificationServiceConstants.HTML_LOGO_CID_PLACEHOLDER;

public class AWSEmailProvider implements EmailProvider {
    private static final Logger LOGGER = LoggerFactory.getLogger(AWSEmailProvider.class);
    private final AmazonSimpleEmailService ses;

    @Override
    public boolean sendEmail(String subject, String body, boolean status, Collection<String> recipients, String from, byte[] logoImage) {
        try {
            Session session = Session.getDefaultInstance(new Properties());

            // Create a new MimeMessage object.
            MimeMessage message = new MimeMessage(session);

            // Add subject, from and to lines.
            message.setSubject(subject, CHARSET_UTF_8);
            message.setFrom(new InternetAddress(from));
            message.setRecipients(javax.mail.Message.RecipientType.BCC, InternetAddress.parse(String.join(",", recipients)));

            // Create a multipart/alternative child container.
            MimeMultipart msgBody = new MimeMultipart("alternative");

            // Create a wrapper for the HTML and text parts.
            MimeBodyPart wrap = new MimeBodyPart();

            // Set the text part.
            MimeBodyPart textPart = new MimeBodyPart();
            textPart.setContent(body, "text/plain; charset=" + CHARSET_UTF_8);

            // Set the HTML part.
            MimeBodyPart htmlPart = new MimeBodyPart();
            htmlPart.setContent(body, "text/html; charset=" + CHARSET_UTF_8);

            // Add the text and HTML parts to the child container.
            msgBody.addBodyPart(textPart);
            msgBody.addBodyPart(htmlPart);

            // Add the child container to the wrapper object.
            wrap.setContent(msgBody);

            // Create a multipart/mixed parent container.
            MimeMultipart msgParent = new MimeMultipart("related");

            // Add the multipart/alternative part to the message.
            msgParent.addBodyPart(wrap);

            // Add the parent container to the message.
            message.setContent(msgParent);

            if (logoImage != null) {
                MimeBodyPart logo = new MimeBodyPart();
                logo.setContent(logoImage, "image/png");
                logo.setContentID(HTML_LOGO_CID_PLACEHOLDER);
                logo.setDisposition(MimeBodyPart.INLINE);
                // Add the attachment to the message.
                msgParent.addBodyPart(logo);
            }

            try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
                message.writeTo(outputStream);
                RawMessage rawMessage = new RawMessage(ByteBuffer.wrap(outputStream.toByteArray()));
                SendRawEmailRequest rawEmailRequest = new SendRawEmailRequest(rawMessage);
                SendRawEmailResult result = ses.sendRawEmail(rawEmailRequest);
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug("Email with messageId={} sent successfully.", result.getMessageId());
                }
                status = status && result != null;
            }
        } catch (Exception ex) {
            LOGGER.error("The email could not be sent. Error message: {}", ex.getMessage());
            status = false;
        }
        return status;    }

    AWSEmailProvider() {
        this(initSES());
    }

    AWSEmailProvider(AmazonSimpleEmailService ses) {
        this.ses = ses;
    }

    private static AmazonSimpleEmailService initSES() {
        ///CLOVER:OFF
        Region region = Regions.getCurrentRegion();
        if (region == null) {
            region = Region.getRegion(Regions.US_EAST_1);
        }
        return AmazonSimpleEmailServiceClientBuilder.standard().withRegion(region.getName()).build();
        ///CLOVER:ON
    }
}
