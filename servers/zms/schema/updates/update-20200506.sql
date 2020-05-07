ALTER TABLE `zms_server`.`role` ADD `user_authority_filter` VARCHAR(512) NOT NULL DEFAULT '';
ALTER TABLE `zms_server`.`role` ADD `user_authority_expiration` VARCHAR(64) NOT NULL DEFAULT '';