ALTER TABLE `zms_server`.`principal_group` ADD `delete_protection` TINYINT(1) NOT NULL DEFAULT 0;
ALTER TABLE `zms_server`.`pending_principal_group_member` ADD `pending_state` VARCHAR(12) NOT NULL DEFAULT 'ADD';
