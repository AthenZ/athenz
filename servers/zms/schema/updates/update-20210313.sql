ALTER TABLE `zms_server`.`domain` ADD `business_service` VARCHAR(256) NOT NULL DEFAULT '';
CREATE INDEX `idx_business_service` ON `zms_server`.`domain` (`business_service` ASC);
ALTER TABLE `zms_server`.`principal_group` ADD `member_expiry_days` INT NOT NULL DEFAULT 0;
ALTER TABLE `zms_server`.`principal_group` ADD `service_expiry_days` INT NOT NULL DEFAULT 0;
