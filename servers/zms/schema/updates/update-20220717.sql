ALTER TABLE `zms_server`.`domain` ADD `member_purge_expiry_days` INT NOT NULL DEFAULT 0;
ALTER TABLE `zms_server`.`role` ADD `description` VARCHAR(4096) NOT NULL DEFAULT '';
ALTER TABLE `zms_server`.`policy` ADD `description` VARCHAR(4096) NOT NULL DEFAULT '';
