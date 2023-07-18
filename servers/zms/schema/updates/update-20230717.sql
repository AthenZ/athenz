CREATE TABLE IF NOT EXISTS `zms_server`.`service_tags` (
    `service_id` INT UNSIGNED NOT NULL,
    `key` VARCHAR(64) CHARACTER SET 'utf8' COLLATE 'utf8_bin' NOT NULL,
    `value` VARCHAR(256) NOT NULL,
    PRIMARY KEY (`service_id`, `key`, `value`),
    INDEX `tag_key_val_sec_idx` (`key` ASC, `value` ASC),
    CONSTRAINT `fk_service_tag_service`
    FOREIGN KEY (`service_id`)
    REFERENCES `zms_server`.`service` (`service_id`)
    ON DELETE CASCADE
    ON UPDATE NO ACTION)
    ENGINE = InnoDB;