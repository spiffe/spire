SELECT count(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE table_schema = 'spire' AND table_name = 'registered_entries' AND column_name = 'store_svid';

ALTER TABLE `registered_entries` ADD `store_svid` boolean
SELECT count(*) FROM INFORMATION_SCHEMA.STATISTICS WHERE table_schema = 'spire' AND table_name = 'registered_entries' AND index_name = 'uix_registered_entries_entry_id'

UPDATE `migrations` SET `code_version` = '1.0.4', `updated_at` = '2022-10-14 08:25:11.298163', `version` = 16
COMMIT
START TRANSACTION
SELECT count(*) FROM INFORMATION_SCHEMA.TABLES WHERE table_schema = 'spire' AND table_name = 'federated_trust_domains'

CREATE TABLE `federated_trust_domains` (`id` int unsigned AUTO_INCREMENT,`created_at` timestamp NULL,`updated_at` timestamp NULL,`trust_domain` varchar(255) NOT NULL,`bundle_endpoint_url` varchar(255),`bundle_endpoint_profile` varchar(255),`endpoint_spiffe_id` varchar(255),`implicit` boolean , PRIMARY KEY (`id`))

SELECT count(*) FROM INFORMATION_SCHEMA.STATISTICS WHERE table_schema = 'spire' AND table_name = 'federated_trust_domains' AND index_name = 'uix_federated_trust_domains_trust_domain'
CREATE UNIQUE INDEX uix_federated_trust_domains_trust_domain ON `federated_trust_domains`(trust_domain)

UPDATE `migrations` SET `code_version` = '1.0.4', `updated_at` = '2022-10-14 08:25:11.776918', `version` = 17
COMMIT

START TRANSACTION
SELECT * FROM `bundles`  WHERE (trust_domain = 'spiffe://myntra.com')
ROLLBACK
