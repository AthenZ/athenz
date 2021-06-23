CREATE TABLE IF NOT EXISTS `zms_server`.`assertion_condition` (
  `assertion_id` INT UNSIGNED NOT NULL,
  `condition_id` INT NOT NULL,
  `key` VARCHAR(64) NOT NULL,
  `operator` VARCHAR(16) NOT NULL,
  `value` VARCHAR(2048) NOT NULL,
  PRIMARY KEY (`assertion_id`, `condition_id`, `key`),
  INDEX `fk_condition_assertion_idx` (`assertion_id` ASC),
  CONSTRAINT `assertion_id`
    FOREIGN KEY (`assertion_id`)
    REFERENCES `zms_server`.`assertion` (`assertion_id`)
    ON DELETE CASCADE
    ON UPDATE NO ACTION)
    ENGINE = InnoDB;