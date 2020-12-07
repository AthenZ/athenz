ALTER TABLE `zms_server`.`quota` ADD `principal_group` INT UNSIGNED NOT NULL DEFAULT 100;
ALTER TABLE `zms_server`.`quota` ADD `principal_group_member` INT UNSIGNED NOT NULL DEFAULT 100;
CREATE TABLE IF NOT EXISTS `zms_server`.`principal_group` (
  `group_id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `domain_id` INT UNSIGNED NOT NULL,
  `name` VARCHAR(512) NOT NULL,
  `modified` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  `created` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `audit_enabled` TINYINT(1) NOT NULL DEFAULT 0,
  `self_serve` TINYINT(1) NOT NULL DEFAULT 0,
  `review_enabled` TINYINT(1) NOT NULL DEFAULT 0,
  `notify_roles` VARCHAR(512) NOT NULL DEFAULT '',
  `last_reviewed_time` DATETIME(3) NULL,
  `user_authority_filter` VARCHAR(512) NOT NULL DEFAULT '',
  `user_authority_expiration` VARCHAR(64) NOT NULL DEFAULT '',
  PRIMARY KEY (`group_id`),
  UNIQUE INDEX `uq_domain_group` (`domain_id` ASC, `name` ASC),
  CONSTRAINT `fk_group_domain`
    FOREIGN KEY (`domain_id`)
    REFERENCES `zms_server`.`domain` (`domain_id`)
    ON DELETE CASCADE
    ON UPDATE NO ACTION)
ENGINE = InnoDB;
CREATE TABLE IF NOT EXISTS `zms_server`.`principal_group_member` (
  `group_id` INT UNSIGNED NOT NULL,
  `principal_id` INT UNSIGNED NOT NULL,
  `expiration` DATETIME(3) NULL,
  `active` TINYINT(1) NOT NULL DEFAULT 1,
  `system_disabled` INT NOT NULL DEFAULT 0,
  `audit_ref` VARCHAR(512) NULL,
  `last_notified_time` DATETIME(3) NULL,
  `server` VARCHAR(512) NULL,
  `req_principal` VARCHAR(512) NOT NULL DEFAULT '',
  INDEX `idx_principal` (`principal_id` ASC, `group_id` ASC),
  INDEX `fq_group_member_group_idx` (`group_id` ASC),
  CONSTRAINT `fk_group_member_group`
    FOREIGN KEY (`group_id`)
    REFERENCES `zms_server`.`principal_group` (`group_id`)
    ON DELETE CASCADE
    ON UPDATE NO ACTION,
  CONSTRAINT `fk_group_member_principal`
    FOREIGN KEY (`principal_id`)
    REFERENCES `zms_server`.`principal` (`principal_id`)
    ON DELETE CASCADE
    ON UPDATE NO ACTION)
ENGINE = InnoDB;
CREATE TABLE IF NOT EXISTS `zms_server`.`pending_principal_group_member` (
  `group_id` INT UNSIGNED NOT NULL,
  `principal_id` INT UNSIGNED NOT NULL,
  `expiration` DATETIME(3) NULL,
  `audit_ref` VARCHAR(512) NULL,
  `req_time` DATETIME(3) NULL DEFAULT CURRENT_TIMESTAMP(3),
  `last_notified_time` DATETIME(3) NULL DEFAULT CURRENT_TIMESTAMP(3),
  `server` VARCHAR(255) NULL,
  `req_principal` VARCHAR(512) NOT NULL DEFAULT '',
  PRIMARY KEY (`group_id`, `principal_id`),
  INDEX `idx_principal` (`principal_id` ASC, `group_id` ASC),
  CONSTRAINT `fk_pending_group_member_group`
    FOREIGN KEY (`group_id`)
    REFERENCES `zms_server`.`principal_group` (`group_id`)
    ON DELETE CASCADE
    ON UPDATE NO ACTION,
  CONSTRAINT `fk_pending_group_member_principal`
    FOREIGN KEY (`principal_id`)
    REFERENCES `zms_server`.`principal` (`principal_id`)
    ON DELETE CASCADE
    ON UPDATE NO ACTION)
ENGINE = InnoDB;
CREATE TABLE IF NOT EXISTS `zms_server`.`principal_group_audit_log` (
  `audit_log_id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `group_id` INT UNSIGNED NOT NULL,
  `admin` VARCHAR(512) NOT NULL,
  `member` VARCHAR(512) NOT NULL,
  `created` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `action` VARCHAR(32) NOT NULL,
  `audit_ref` VARCHAR(512) NOT NULL,
  PRIMARY KEY (`audit_log_id`),
  INDEX `fk_group_audit_log_group_id_idx` (`group_id` ASC),
  CONSTRAINT `fk_group_audit_log_group`
    FOREIGN KEY (`group_id`)
    REFERENCES `zms_server`.`principal_group` (`group_id`)
    ON DELETE CASCADE
    ON UPDATE NO ACTION)
ENGINE = InnoDB;

