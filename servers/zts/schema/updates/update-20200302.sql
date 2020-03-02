ALTER TABLE `zts_store`.`certificates`
  ADD COLUMN `lastNotifiedTime` DATETIME(3) NULL,
  ADD COLUMN `lastNotifiedServer` VARCHAR(512) NULL,
  ADD COLUMN `expiryTime` DATETIME(3) NULL,
  ADD COLUMN `hostName` VARCHAR(512) NULL;