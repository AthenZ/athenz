ALTER TABLE `zms_server`.`role` ADD `principal_domain_filter` VARCHAR(1024) NOT NULL DEFAULT '';
ALTER TABLE `zms_server`.`principal_group` ADD `principal_domain_filter` VARCHAR(1024) NOT NULL DEFAULT '';
