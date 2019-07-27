ALTER TABLE `zms_server`.`role_member` ADD `active` TINYINT(1) NOT NULL DEFAULT 1;
ALTER TABLE `zms_server`.`role` ADD `self_serve` TINYINT(1) NOT NULL DEFAULT 0;
