CREATE TABLE IF NOT EXISTS `zms_server`.`domain_tags` (
    `domain_id` INT UNSIGNED NOT NULL,
    `key` VARCHAR(64) NOT NULL,
    `value` VARCHAR(64) NOT NULL,
    PRIMARY KEY (`key`, `value`, `domain_id`),
    CONSTRAINT `fk_domain_tag_domain`
      FOREIGN KEY (`domain_id`)
      REFERENCES `zms_server`.`domain` (`domain_id`)
      ON DELETE CASCADE
      ON UPDATE NO ACTION)
ENGINE = InnoDB;
