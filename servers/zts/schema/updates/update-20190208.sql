ALTER TABLE `zts_store`.`certificates` DROP PRIMARY KEY, ADD PRIMARY KEY (`provider`, `instanceId`, `service`);
