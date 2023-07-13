CREATE TABLE IF NOT EXISTS `zms_server`.`policy_tags` (
    `policy_id` INT UNSIGNED NOT NULL,
    `key` VARCHAR(64) CHARACTER SET 'utf8' COLLATE 'utf8_bin' NOT NULL,
    `value` VARCHAR(256) NOT NULL,
    PRIMARY KEY (`policy_id`, `key`, `value`),
    INDEX `tag_key_val_sec_idx` (`key` ASC, `value` ASC),
    CONSTRAINT `fk_policy_tag_policy`
    FOREIGN KEY (`policy_id`)
    REFERENCES `zms_server`.`policy` (`policy_id`)
    ON DELETE CASCADE
    ON UPDATE NO ACTION)
    ENGINE = InnoDB;