ALTER TABLE `zms_server`.`service` ADD `x509_cert_signer_keyid` VARCHAR(64) NOT NULL DEFAULT '';
ALTER TABLE `zms_server`.`service` ADD `ssh_cert_signer_keyid` VARCHAR(64) NOT NULL DEFAULT '';
ALTER TABLE `zms_server`.`service` ADD `creds` VARCHAR(64) NOT NULL DEFAULT '';
