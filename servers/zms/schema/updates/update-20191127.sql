ALTER TABLE `zms_server`.`domain` ADD `service_cert_expiry_mins` INT NOT NULL DEFAULT 0;
ALTER TABLE `zms_server`.`domain` ADD `role_cert_expiry_mins` INT NOT NULL DEFAULT 0;
ALTER TABLE `zms_server`.`domain` ADD `sign_algorithm` VARCHAR(64) NOT NULL DEFAULT '';
ALTER TABLE `zms_server`.`role` ADD `cert_expiry_mins` INT NOT NULL DEFAULT 0;
ALTER TABLE `zms_server`.`role` ADD `sign_algorithm` VARCHAR(64) NOT NULL DEFAULT '';
