CREATE TABLE IF NOT EXISTS `zms_server`.`role_tags` (
  `role_id` INT UNSIGNED NOT NULL,
  `key` VARCHAR(64) NOT NULL,
  `value` VARCHAR(64) NOT NULL,
  PRIMARY KEY (`role_id`, `key`, `value`),
  INDEX `fk_role_tag_role_idx` (`role_id` ASC),
  INDEX `tag_key_sec_idx` (`key` ASC),
  INDEX `tag_value_sec_idx` (`value` ASC),
  CONSTRAINT `fk_role_tag_role`
    FOREIGN KEY (`role_id`)
    REFERENCES `zms_server`.`role` (`role_id`)
    ON DELETE CASCADE
    ON UPDATE NO ACTION)
ENGINE = InnoDB;
