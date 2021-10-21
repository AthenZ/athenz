CREATE TABLE IF NOT EXISTS `zms_server`.`group_tags` (
  `group_id` INT UNSIGNED NOT NULL,
  `key` VARCHAR(64) NOT NULL,
  `value` VARCHAR(256) NOT NULL,
  PRIMARY KEY (`group_id`, `key`, `value`),
  INDEX `tag_key_val_sec_idx` (`key` ASC, `value` ASC),
  CONSTRAINT `fk_group_tag_group`
    FOREIGN KEY (`group_id`)
    REFERENCES `zms_server`.`principal_group` (`group_id`)
    ON DELETE CASCADE
    ON UPDATE NO ACTION)
ENGINE = InnoDB;