CREATE TABLE IF NOT EXISTS `zms_server`.`service_domain_dependency` (
    `domain` VARCHAR(512) NOT NULL,
    `service` VARCHAR(1024) NOT NULL,
    PRIMARY KEY (`domain`(128), `service`(128)),
    INDEX `idx_service` (`service`(256) ASC),
    INDEX `idx_domain` (`domain`(256) ASC))
ENGINE = InnoDB;

