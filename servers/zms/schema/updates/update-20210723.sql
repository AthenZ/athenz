ALTER TABLE `zms_server`.`policy` ADD `version` VARCHAR(32) NOT NULL DEFAULT '0';
ALTER TABLE `zms_server`.`policy` ADD `active` TINYINT(1) NOT NULL DEFAULT 1;
ALTER TABLE `zms_server`.`policy`
  DROP INDEX `uq_domain_policy`,
  ADD UNIQUE INDEX `uq_domain_policy` (`name` ASC, `domain_id` ASC, `version` ASC);
