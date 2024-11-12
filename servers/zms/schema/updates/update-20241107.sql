ALTER TABLE `zms_server`.`domain` ADD `slack_channel` VARCHAR(80) NOT NULL DEFAULT '';
ALTER TABLE `zms_server`.`role` ADD `notify_details` VARCHAR(512) NOT NULL DEFAULT '';
ALTER TABLE `zms_server`.`principal_group` ADD `notify_details` VARCHAR(512) NOT NULL DEFAULT '';
