ALTER TABLE `zms_server`.`domain` ADD `product_id` VARCHAR(128) NOT NULL DEFAULT '';
CREATE INDEX `idx_product_id` ON `zms_server`.`domain` (`product_id` ASC);
