ALTER TABLE `zms_server`.`domain` DROP INDEX `idx_account`;
ALTER TABLE `zms_server`.`domain` MODIFY `account` VARCHAR(2048) NOT NULL DEFAULT '';
ALTER TABLE `zms_server`.`domain` ADD INDEX `idx_account` (`account`(255) ASC);
