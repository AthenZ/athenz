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

import com.amazonaws.util.IOUtils;
import com.yahoo.athenz.common.server.notification.EmailProvider;
import com.yahoo.athenz.common.server.notification.Notification;
import com.yahoo.athenz.common.server.notification.NotificationEmail;
import com.yahoo.athenz.common.server.notification.NotificationService;
import jakarta.mail.Part;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.mail.MessagingException;
import jakarta.mail.Session;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeBodyPart;
import jakarta.mail.internet.MimeMessage;
import jakarta.mail.internet.MimeMultipart;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

import static com.yahoo.athenz.common.server.notification.NotificationServiceConstants.*;

/*
 * Email based notification service.
 */
public class EmailNotificationService implements NotificationService {

    private static final Logger LOGGER = LoggerFactory.getLogger(EmailNotificationService.class);

    private static final int SES_RECIPIENTS_LIMIT_PER_MESSAGE = 50;

    private static final String EMAIL_TEMPLATE_ATHENZ_LOGO = "emails/athenz-logo-white.png";
    private static final String PROP_NOTIFICATION_EMAIL_DOMAIN_FROM = "athenz.notification_email_domain_from";
    private static final String PROP_NOTIFICATION_EMAIL_FROM = "athenz.notification_email_from";
    private static final String AT = "@";

    private final EmailProvider emailProvider;
    private final String emailDomainFrom;
    private final String from;

    private final byte[] logoImage;

    public EmailNotificationService(EmailProvider emailProvider) {
        this.emailProvider = emailProvider;
        emailDomainFrom = System.getProperty(PROP_NOTIFICATION_EMAIL_DOMAIN_FROM);
        from = System.getProperty(PROP_NOTIFICATION_EMAIL_FROM);
        logoImage = readBinaryFromFile(EMAIL_TEMPLATE_ATHENZ_LOGO);
    }

    byte[] readBinaryFromFile(String fileName) {

        byte[] fileByteArray = null;
        URL resource = getClass().getClassLoader().getResource(fileName);
        if (resource != null) {
            try (InputStream fileStream = resource.openStream()) {
                //convert to byte array
                fileByteArray = IOUtils.toByteArray(fileStream);

            } catch (IOException ex) {
                LOGGER.error("Could not read file: {}. Error message: {}", fileName, ex.getMessage());
            }
        }
        return fileByteArray;
    }

    @Override
    public boolean notify(Notification notification) {
        if (notification == null) {
            return false;
        }

        NotificationEmail notificationAsEmail = notification.getNotificationAsEmail();

        if (notificationAsEmail == null) {
            return false;
        }

        final String subject = notificationAsEmail.getSubject();
        final String body = notificationAsEmail.getBody();
        Set<String> recipients = notificationAsEmail.getFullyQualifiedRecipientsEmail();
            if (sendEmail(recipients, subject, body)) {
            LOGGER.info("Successfully sent email notification. Subject={}, Recipients={}", subject, recipients);
            return true;
        } else {
            LOGGER.error("Failed sending email notification. Subject={}, Recipients={}", subject, recipients);
            return false;
        }
    }

    boolean sendEmail(Set<String> recipients, String subject, String body) {
        final AtomicInteger counter = new AtomicInteger();
        // SES imposes a limit of 50 recipients. So we convert the recipients into batches
        if (recipients.size() > SES_RECIPIENTS_LIMIT_PER_MESSAGE) {
            final Collection<List<String>> recipientsBatch = recipients.stream()
                    .collect(Collectors.groupingBy(it -> counter.getAndIncrement() / SES_RECIPIENTS_LIMIT_PER_MESSAGE))
                    .values();
            boolean status = true;
            for (List<String> recipientsSegment : recipientsBatch) {
                if (!sendEmailMIME(subject, body, recipientsSegment)) {
                    status = false;
                }
            }
            return status;
        } else {
            return sendEmailMIME(subject, body, new ArrayList<>(recipients));
        }
    }

    private MimeMessage getMimeMessage(String subject, String body, Collection<String> recipients, String from, byte[] logoImage) throws MessagingException {
        Session session = Session.getDefaultInstance(new Properties());

        // Create a new MimeMessage object.
        MimeMessage message = new MimeMessage(session);

        // Add subject, from and to lines.
        message.setSubject(subject, CHARSET_UTF_8);
        message.setFrom(new InternetAddress(from));
        message.setRecipients(jakarta.mail.Message.RecipientType.BCC, InternetAddress.parse(String.join(",", recipients)));

        // Set the HTML part.
        MimeBodyPart htmlPart = new MimeBodyPart();
        htmlPart.setContent(body, "text/html; charset=" + CHARSET_UTF_8);

        // Create a multipart/mixed parent container.
        MimeMultipart msgParent = new MimeMultipart("related");

        // Add the body to the message.
        msgParent.addBodyPart(htmlPart);

        // Add the parent container to the message.
        message.setContent(msgParent);

        if (logoImage != null) {
            MimeBodyPart logo = new MimeBodyPart();
            logo.setContent(logoImage, "image/png");
            logo.setContentID(HTML_LOGO_CID_PLACEHOLDER);
            logo.setDisposition(Part.INLINE);
            // Add the attachment to the message.
            msgParent.addBodyPart(logo);
        }

        return message;
    }

    private boolean sendEmailMIME(String subject, String body, Collection<String> recipients) {
        MimeMessage mimeMessage;
        try {
            mimeMessage = getMimeMessage(subject, body, recipients, from + AT + emailDomainFrom, logoImage);
        } catch (MessagingException ex) {
            LOGGER.error("The email could not be sent. Error message: {}", ex.getMessage());
            return false;
        }

        return emailProvider.sendEmail(recipients, from + AT + emailDomainFrom, mimeMessage);
    }
}
