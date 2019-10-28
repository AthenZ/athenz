ALTER TABLE `zms_server`.`domain` ADD `member_expiry_days` INT NOT NULL DEFAULT 0;
ALTER TABLE `zms_server`.`domain` ADD `token_expiry_mins` INT NOT NULL DEFAULT 0;
ALTER TABLE `zms_server`.`role` ADD `member_expiry_days` INT NOT NULL DEFAULT 0;
ALTER TABLE `zms_server`.`role` ADD `token_expiry_mins` INT NOT NULL DEFAULT 0;
