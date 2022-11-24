ALTER TABLE `zms_server`.`domain` ADD `gcp_project` VARCHAR(128) NOT NULL DEFAULT '';
CREATE INDEX `idx_gcp` ON `zms_server`.`domain` (`gcp_project` ASC);
