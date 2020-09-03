ALTER TABLE `zms_server`.`domain` ADD `group_expiry_days` INT NOT NULL DEFAULT 0;
ALTER TABLE `zms_server`.`role` ADD `group_expiry_days` INT NOT NULL DEFAULT 0;
