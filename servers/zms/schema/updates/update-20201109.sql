CREATE TABLE IF NOT EXISTS `zms_server`.`role_tags` (
  `role_id` INT UNSIGNED NOT NULL,
  `key` VARCHAR(64) NOT NULL,
  `value` VARCHAR(64) NOT NULL,
  PRIMARY KEY (`role_id`, `key`, `value`),
  INDEX `tag_key_val_sec_idx` (`key` ASC, `value` ASC),
  CONSTRAINT `fk_role_tag_role`
    FOREIGN KEY (`role_id`)
    REFERENCES `zms_server`.`role` (`role_id`)
    ON DELETE CASCADE
    ON UPDATE NO ACTION)
ENGINE = InnoDB;
