ALTER TABLE `zms_server`.`role` ADD `self_renew` TINYINT(1) NOT NULL DEFAULT 0;
ALTER TABLE `zms_server`.`role` ADD `self_renew_mins` INT NOT NULL DEFAULT 0;
ALTER TABLE `zms_server`.`principal_group` ADD `self_renew` TINYINT(1) NOT NULL DEFAULT 0;
ALTER TABLE `zms_server`.`principal_group` ADD `self_renew_mins` INT NOT NULL DEFAULT 0;
