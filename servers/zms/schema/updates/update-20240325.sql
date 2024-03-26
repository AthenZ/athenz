ALTER TABLE `zms_server`.`domain` ADD `resource_owner` VARCHAR(256) NOT NULL DEFAULT '';
ALTER TABLE `zms_server`.`role` ADD `resource_owner` VARCHAR(256) NOT NULL DEFAULT '';
ALTER TABLE `zms_server`.`policy` ADD `resource_owner` VARCHAR(256) NOT NULL DEFAULT '';
ALTER TABLE `zms_server`.`service` ADD `resource_owner` VARCHAR(256) NOT NULL DEFAULT '';
ALTER TABLE `zms_server`.`principal_group` ADD `resource_owner` VARCHAR(256) NOT NULL DEFAULT '';
