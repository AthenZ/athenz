CREATE TABLE IF NOT EXISTS `zms_server`.`domain_contacts` (
    `domain_id` INT UNSIGNED NOT NULL,
    `type` VARCHAR(64) NOT NULL,
    `name` VARCHAR(512) NOT NULL,
    PRIMARY KEY (`domain_id`, `type`),
    UNIQUE INDEX `uq_domain_contact` (`domain_id` ASC, `type` ASC),
    INDEX `idx_contact_name` (`name` ASC),
    CONSTRAINT `fk_domain_contacts_domain`
      FOREIGN KEY (`domain_id`)
          REFERENCES `zms_server`.`domain` (`domain_id`)
          ON DELETE CASCADE
          ON UPDATE NO ACTION)
    ENGINE = InnoDB;
