ALTER TABLE `zms_server`.`role_member` ADD `review_reminder` DATETIME(3) NULL AFTER `expiration`;
ALTER TABLE `zms_server`.`role_member` ADD `review_last_notified_time` DATETIME(3) NULL AFTER `req_principal`;
ALTER TABLE `zms_server`.`role_member` ADD `review_server` VARCHAR(255) NULL AFTER `review_last_notified_time`;
ALTER TABLE `zms_server`.`pending_role_member` ADD `review_reminder` DATETIME(3) NULL AFTER `expiration`;