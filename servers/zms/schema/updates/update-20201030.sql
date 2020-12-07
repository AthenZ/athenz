ALTER TABLE `zms_server`.`domain` ADD `azure_subscription` VARCHAR(128) NOT NULL DEFAULT '';
CREATE INDEX `idx_azure` ON `zms_server`.`domain` (`azure_subscription` ASC);
