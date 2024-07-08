ALTER TABLE `zms_server`.`domain` ADD `x509_cert_signer_keyid` VARCHAR(64) NOT NULL DEFAULT '';
ALTER TABLE `zms_server`.`domain` ADD `ssh_cert_signer_keyid` VARCHAR(64) NOT NULL DEFAULT '';
