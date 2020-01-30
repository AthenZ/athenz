ALTER TABLE `zms_server`.`role` ADD `review_enabled` TINYINT(1) NOT NULL DEFAULT 0;
ALTER TABLE `zms_server`.`role` ADD `notify_roles` VARCHAR(512) NOT NULL DEFAULT '';
ALTER TABLE `zms_server`.`role` ADD `last_reviewed_time` DATETIME(3) NULL;
ALTER TABLE `zms_server`.`role_member` ADD `req_principal` VARCHAR(512) NOT NULL DEFAULT '';
ALTER TABLE `zms_server`.`pending_role_member` ADD `req_principal` VARCHAR(512) NOT NULL DEFAULT '';
