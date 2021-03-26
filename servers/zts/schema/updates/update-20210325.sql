CREATE TABLE IF NOT EXISTS `zts_store`.`workloads` (
    `provider` VARCHAR(384) NOT NULL,
    `service` VARCHAR(384) NOT NULL,
    `ip` VARCHAR(64) NOT NULL,
    `instanceId` VARCHAR(256) NOT NULL,
    `creationTime` DATETIME(3) NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updateTime` DATETIME(3) NULL DEFAULT CURRENT_TIMESTAMP(3),
    PRIMARY KEY (`instanceId`, `ip`, `service`),
    INDEX `idx_service` (`service` ASC),
    INDEX `idx_ip` (`ip` ASC))
    ENGINE = InnoDB;