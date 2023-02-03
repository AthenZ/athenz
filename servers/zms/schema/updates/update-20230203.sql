-- -----------------------------------------------------
-- SQL UPDATE 20200827 included a create TABLE command
-- for the principal_group_member table. However, the
-- table definition didn't include the primary key
-- definition. So if your DB server was installed after
-- that date with the complete zms_server.sql script,
-- then this update is not necessary.
-- -----------------------------------------------------
ALTER TABLE `zms_server`.`principal_group_member` ADD PRIMARY KEY (`group_id`, `principal_id`);
