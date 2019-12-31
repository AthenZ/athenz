ALTER TABLE `zms_server`.`domain` ADD `service_expiry_days` INT NOT NULL DEFAULT 0;
ALTER TABLE `zms_server`.`role` ADD `service_expiry_days` INT NOT NULL DEFAULT 0;
