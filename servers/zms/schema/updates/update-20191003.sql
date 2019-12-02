CREATE TABLE IF NOT EXISTS `zms_server`.`pending_role_member` (
  `role_id` INT UNSIGNED NOT NULL,
  `principal_id` INT UNSIGNED NOT NULL,
  `expiration` DATETIME(3) NULL,
  `audit_ref` VARCHAR(512) NULL COMMENT 'Audit reference mandatory for membership changes of audit enabled / self serve roles',
  `req_time` DATETIME(3) NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`role_id`, `principal_id`),
  INDEX `idx_principal` (`principal_id` ASC, `role_id` ASC),
  CONSTRAINT `fk_pending_role_member_role`
    FOREIGN KEY (`role_id`)
    REFERENCES `zms_server`.`role` (`role_id`)
    ON DELETE CASCADE
    ON UPDATE NO ACTION,
  CONSTRAINT `fk_pending_role_member_principal`
    FOREIGN KEY (`principal_id`)
    REFERENCES `zms_server`.`principal` (`principal_id`)
    ON DELETE CASCADE
    ON UPDATE NO ACTION)
ENGINE = InnoDB;
