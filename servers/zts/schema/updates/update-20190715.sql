ALTER TABLE `zts_store`.`certificates`
  MODIFY COLUMN `provider` VARCHAR(384),
  MODIFY COLUMN `instanceId` VARCHAR(256),
  MODIFY COLUMN `service` VARCHAR(384);
