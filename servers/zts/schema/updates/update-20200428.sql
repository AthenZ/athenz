CREATE TABLE IF NOT EXISTS `zts_store`.`ssh_certificates` (
  `instanceId` VARCHAR(256) NOT NULL,
  `service` VARCHAR(384) NOT NULL,
  `principals` VARCHAR(1024) NOT NULL DEFAULT '',
  `clientIP` VARCHAR(64) NOT NULL DEFAULT '',
  `privateIP` VARCHAR(64) NOT NULL DEFAULT '',
  `issueTime` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`instanceId`, `service`))
ENGINE = InnoDB;
