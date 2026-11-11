CREATE TABLE IF NOT EXISTS `zms_server`.`policy_bundle` (
  `bundle_id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `domain_id` INT UNSIGNED NOT NULL,
  `name` VARCHAR(512) NOT NULL,
  `engine` VARCHAR(32) NOT NULL DEFAULT 'rego',
  `version` VARCHAR(32) NOT NULL DEFAULT '0',
  `active` TINYINT(1) NOT NULL DEFAULT 1,
  `roots` VARCHAR(2048) NOT NULL DEFAULT '',
  `description` VARCHAR(4096) NOT NULL DEFAULT '',
  `modified` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  `created` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`bundle_id`),
  INDEX `fk_policy_bundle_domain_idx` (`domain_id` ASC),
  UNIQUE INDEX `uq_domain_policy_bundle` (`name` ASC, `domain_id` ASC, `version` ASC),
  CONSTRAINT `fk_policy_bundle_domain`
    FOREIGN KEY (`domain_id`)
    REFERENCES `zms_server`.`domain` (`domain_id`)
    ON DELETE CASCADE
    ON UPDATE NO ACTION)
ENGINE = InnoDB;

CREATE TABLE IF NOT EXISTS `zms_server`.`policy_bundle_file` (
  `bundle_id` INT UNSIGNED NOT NULL,
  `path` VARCHAR(512) CHARACTER SET 'ascii' COLLATE 'ascii_bin' NOT NULL,
  `content` MEDIUMTEXT NOT NULL,
  `sha256` CHAR(64) NOT NULL,
  `modified` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`bundle_id`, `path`),
  CONSTRAINT `fk_policy_bundle_file_bundle`
    FOREIGN KEY (`bundle_id`)
    REFERENCES `zms_server`.`policy_bundle` (`bundle_id`)
    ON DELETE CASCADE
    ON UPDATE NO ACTION)
ENGINE = InnoDB;
