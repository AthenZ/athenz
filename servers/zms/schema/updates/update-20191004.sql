ALTER TABLE `zms_server`.`pending_role_member` MODIFY `req_time` DATETIME(3) NULL DEFAULT CURRENT_TIMESTAMP(3);
ALTER TABLE `zms_server`.`pending_role_member` ADD `last_notified_time` DATETIME(3) NULL DEFAULT CURRENT_TIMESTAMP(3);
ALTER TABLE `zms_server`.`pending_role_member` ADD `server` VARCHAR(255) NULL;
