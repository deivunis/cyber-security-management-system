-- --------------------------------------------------------
-- Host:                         REDACTED
-- Server version:               PostgreSQL 17.9 (Debian 17.9-0+deb13u1) on x86_64-pc-linux-gnu, compiled by gcc (Debian 14.2.0-19) 14.2.0, 64-bit
-- Server OS:                    
-- HeidiSQL Version:             12.17.0.7270
-- --------------------------------------------------------

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET NAMES  */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

-- Dumping structure for table public.access_control_lists
CREATE TABLE IF NOT EXISTS "access_control_lists" (
	"id" UUID NOT NULL DEFAULT gen_random_uuid(),
	"entry_type" TEXT NOT NULL,
	"match_type" TEXT NOT NULL,
	"match_value" TEXT NOT NULL,
	"comment" TEXT NULL DEFAULT NULL,
	"is_enabled" BOOLEAN NOT NULL DEFAULT true,
	"created_by" TEXT NOT NULL DEFAULT 'api',
	"created_at" TIMESTAMPTZ NOT NULL DEFAULT now(),
	"updated_at" TIMESTAMPTZ NOT NULL DEFAULT now(),
	PRIMARY KEY ("id"),
	UNIQUE ("entry_type", "match_type", "match_value"),
	CONSTRAINT "access_control_lists_entry_type_chk" CHECK ((entry_type = ANY (ARRAY['whitelist'::text, 'blacklist'::text]))),
	CONSTRAINT "access_control_lists_match_type_chk" CHECK ((match_type = ANY (ARRAY['ip'::text, 'mac'::text])))
)
CREATE INDEX "idx_acl_entry_type" ON "" ("entry_type");
CREATE INDEX "idx_acl_match_type" ON "" ("match_type");
CREATE INDEX "idx_acl_match_value" ON "" ("match_value");
CREATE INDEX "idx_acl_enabled" ON "" ("is_enabled");;

-- Data exporting was unselected.

-- Dumping structure for table public.actions
CREATE TABLE IF NOT EXISTS "actions" (
	"id" UUID NOT NULL DEFAULT gen_random_uuid(),
	"incident_id" UUID NULL DEFAULT NULL,
	"device_id" UUID NULL DEFAULT NULL,
	"action_type" TEXT NOT NULL,
	"action_source" TEXT NOT NULL,
	"action_result" TEXT NOT NULL,
	"executed_at" TIMESTAMPTZ NOT NULL DEFAULT now(),
	"details_json" JSONB NOT NULL DEFAULT '{}',
	PRIMARY KEY ("id"),
	CONSTRAINT "actions_device_id_fkey" FOREIGN KEY ("device_id") REFERENCES "devices" ("id") ON UPDATE NO ACTION ON DELETE SET NULL,
	CONSTRAINT "actions_incident_id_fkey" FOREIGN KEY ("incident_id") REFERENCES "incidents" ("id") ON UPDATE NO ACTION ON DELETE SET NULL
)
CREATE INDEX "idx_actions_device_id" ON "" ("device_id");
CREATE INDEX "idx_actions_incident_id" ON "" ("incident_id");
CREATE INDEX "idx_actions_executed_at" ON "" ("executed_at");;

-- Data exporting was unselected.

-- Dumping structure for function public.armor
DELIMITER //
CREATE FUNCTION "armor"() RETURNS TEXT AS $$ pg_armor $$//
DELIMITER ;

-- Dumping structure for function public.armor
DELIMITER //
CREATE FUNCTION "armor"() RETURNS TEXT AS $$ pg_armor $$//
DELIMITER ;

-- Dumping structure for table public.audit_events
CREATE TABLE IF NOT EXISTS "audit_events" (
	"id" SERIALNOT NULL,
	"actor_type" TEXT NOT NULL,
	"actor_name" TEXT NOT NULL,
	"event_type" TEXT NOT NULL,
	"target_type" TEXT NULL DEFAULT NULL,
	"target_id" TEXT NULL DEFAULT NULL,
	"event_time" TIMESTAMPTZ NOT NULL DEFAULT now(),
	"details_json" JSONB NOT NULL DEFAULT '{}',
	PRIMARY KEY ("id")
)
CREATE INDEX "idx_audit_events_time" ON "" ("event_time");
CREATE INDEX "idx_audit_events_event_type" ON "" ("event_type");
CREATE INDEX "idx_audit_events_target" ON "" ("target_type", "target_id");
CREATE INDEX "idx_audit_events_actor" ON "" ("actor_type", "actor_name");;

-- Data exporting was unselected.

-- Dumping structure for function public.cleanup_device_observations
DELIMITER //
CREATE FUNCTION "cleanup_device_observations"(p_keep_days INTEGER, p_batch_size INTEGER) RETURNS INTEGER AS $$ 
DECLARE
  v_deleted integer := 0;
BEGIN
  WITH doomed AS (
    SELECT ctid
    FROM device_observations
    WHERE observed_at < now() - make_interval(days => p_keep_days)
    LIMIT p_batch_size
  )
  DELETE FROM device_observations d
  USING doomed
  WHERE d.ctid = doomed.ctid;

  GET DIAGNOSTICS v_deleted = ROW_COUNT;
  RETURN v_deleted;
END;
 $$//
DELIMITER ;

-- Dumping structure for table public.cpe_dictionary
CREATE TABLE IF NOT EXISTS "cpe_dictionary" (
	"cpe_name" TEXT NOT NULL,
	"cpe_title" TEXT NULL DEFAULT NULL,
	"deprecated" BOOLEAN NOT NULL DEFAULT false,
	"vendor" TEXT NULL DEFAULT NULL,
	"product" TEXT NULL DEFAULT NULL,
	"part" TEXT NULL DEFAULT NULL,
	"version" TEXT NULL DEFAULT NULL,
	"update_value" TEXT NULL DEFAULT NULL,
	"edition" TEXT NULL DEFAULT NULL,
	"language" TEXT NULL DEFAULT NULL,
	"sw_edition" TEXT NULL DEFAULT NULL,
	"target_sw" TEXT NULL DEFAULT NULL,
	"target_hw" TEXT NULL DEFAULT NULL,
	"other_value" TEXT NULL DEFAULT NULL,
	"last_modified_at" TIMESTAMPTZ NULL DEFAULT NULL,
	"raw_json" JSONB NOT NULL DEFAULT '{}',
	"created_at" TIMESTAMPTZ NOT NULL DEFAULT now(),
	"updated_at" TIMESTAMPTZ NOT NULL DEFAULT now(),
	PRIMARY KEY ("cpe_name")
)
CREATE INDEX "idx_cpe_dictionary_deprecated" ON "" ("deprecated");
CREATE INDEX "idx_cpe_dictionary_title_trgm" ON "" ("cpe_title");;

-- Data exporting was unselected.

-- Dumping structure for table public.cpe_match_feed
CREATE TABLE IF NOT EXISTS "cpe_match_feed" (
	"match_criteria_id" TEXT NOT NULL,
	"criteria" TEXT NOT NULL,
	"status" TEXT NULL DEFAULT NULL,
	"version_start_including" TEXT NULL DEFAULT NULL,
	"version_start_excluding" TEXT NULL DEFAULT NULL,
	"version_end_including" TEXT NULL DEFAULT NULL,
	"version_end_excluding" TEXT NULL DEFAULT NULL,
	"vendor" TEXT NULL DEFAULT NULL,
	"product" TEXT NULL DEFAULT NULL,
	"part" TEXT NULL DEFAULT NULL,
	"last_modified_at" TIMESTAMPTZ NULL DEFAULT NULL,
	"cpe_last_modified_at" TIMESTAMPTZ NULL DEFAULT NULL,
	"created_at_remote" TIMESTAMPTZ NULL DEFAULT NULL,
	"matches_json" JSONB NOT NULL DEFAULT '[]',
	"raw_json" JSONB NOT NULL DEFAULT '{}',
	"updated_at" TIMESTAMPTZ NOT NULL DEFAULT now(),
	PRIMARY KEY ("match_criteria_id")
)
CREATE INDEX "idx_cpe_match_feed_modified" ON "" ("last_modified_at");
CREATE INDEX "idx_cpe_match_feed_matches_gin" ON "" ("matches_json");;

-- Data exporting was unselected.

-- Dumping structure for function public.crypt
DELIMITER //
CREATE FUNCTION "crypt"() RETURNS TEXT AS $$ pg_crypt $$//
DELIMITER ;

-- Dumping structure for table public.cve_catalog
CREATE TABLE IF NOT EXISTS "cve_catalog" (
	"cve_id" TEXT NOT NULL,
	"source_system" TEXT NOT NULL DEFAULT 'nvd',
	"cve_year" INTEGER NULL DEFAULT NULL,
	"vendor_project" TEXT NULL DEFAULT NULL,
	"product_name" TEXT NULL DEFAULT NULL,
	"cpe_candidates" JSONB NOT NULL DEFAULT '[]',
	"cvss_base_score" NUMERIC(3,1) NULL DEFAULT NULL,
	"cvss_severity" TEXT NULL DEFAULT NULL,
	"published_at" TIMESTAMPTZ NULL DEFAULT NULL,
	"last_modified_at" TIMESTAMPTZ NULL DEFAULT NULL,
	"description" TEXT NULL DEFAULT NULL,
	"references_json" JSONB NOT NULL DEFAULT '[]',
	"raw_json" JSONB NOT NULL DEFAULT '{}',
	"is_kev" BOOLEAN NOT NULL DEFAULT false,
	"kev_date_added" DATE NULL DEFAULT NULL,
	"kev_due_date" DATE NULL DEFAULT NULL,
	"kev_known_ransomware" BOOLEAN NOT NULL DEFAULT false,
	"kev_notes" TEXT NULL DEFAULT NULL,
	"created_at" TIMESTAMPTZ NOT NULL DEFAULT now(),
	"updated_at" TIMESTAMPTZ NOT NULL DEFAULT now(),
	PRIMARY KEY ("cve_id")
)
CREATE INDEX "idx_cve_catalog_kev" ON "" ("is_kev");
CREATE INDEX "idx_cve_catalog_cvss" ON "" ("cvss_base_score");
CREATE INDEX "idx_cve_catalog_published" ON "" ("published_at");
CREATE INDEX "idx_cve_catalog_modified" ON "" ("last_modified_at");
CREATE INDEX "idx_cve_catalog_cpe_candidates_gin" ON "" ("cpe_candidates");
CREATE INDEX "idx_cve_catalog_description_trgm" ON "" ("description");;

-- Data exporting was unselected.

-- Dumping structure for function public.dearmor
DELIMITER //
CREATE FUNCTION "dearmor"() RETURNS BYTEA AS $$ pg_dearmor $$//
DELIMITER ;

-- Dumping structure for function public.decrypt
DELIMITER //
CREATE FUNCTION "decrypt"() RETURNS BYTEA AS $$ pg_decrypt $$//
DELIMITER ;

-- Dumping structure for function public.decrypt_iv
DELIMITER //
CREATE FUNCTION "decrypt_iv"() RETURNS BYTEA AS $$ pg_decrypt_iv $$//
DELIMITER ;

-- Dumping structure for table public.device_detection_baselines
CREATE TABLE IF NOT EXISTS "device_detection_baselines" (
	"device_id" UUID NOT NULL,
	"metric_name" TEXT NOT NULL,
	"baseline_value" NUMERIC NOT NULL DEFAULT 0,
	"last_value" NUMERIC NOT NULL DEFAULT 0,
	"sample_count" INTEGER NOT NULL DEFAULT 0,
	"first_seen_at" TIMESTAMPTZ NOT NULL DEFAULT now(),
	"last_seen_at" TIMESTAMPTZ NOT NULL DEFAULT now(),
	"details_json" JSONB NOT NULL DEFAULT '{}',
	PRIMARY KEY ("device_id", "metric_name"),
	CONSTRAINT "device_detection_baselines_device_id_fkey" FOREIGN KEY ("device_id") REFERENCES "devices" ("id") ON UPDATE NO ACTION ON DELETE CASCADE
)
CREATE INDEX "idx_device_detection_baselines_metric" ON "" ("metric_name");;

-- Data exporting was unselected.

-- Dumping structure for table public.device_observations
CREATE TABLE IF NOT EXISTS "device_observations" (
	"id" SERIALNOT NULL,
	"device_id" UUID NOT NULL,
	"observed_ip" INET NULL DEFAULT NULL,
	"observed_hostname" TEXT NULL DEFAULT NULL,
	"observation_source" TEXT NOT NULL,
	"observed_at" TIMESTAMPTZ NOT NULL DEFAULT now(),
	"raw_json" JSONB NOT NULL DEFAULT '{}',
	"observed_mac_address" TEXT NULL DEFAULT NULL,
	"observed_vendor" TEXT NULL DEFAULT NULL,
	"observation_kind" TEXT NOT NULL DEFAULT 'passive',
	PRIMARY KEY ("id"),
	CONSTRAINT "device_observations_device_id_fkey" FOREIGN KEY ("device_id") REFERENCES "devices" ("id") ON UPDATE NO ACTION ON DELETE CASCADE
)
CREATE INDEX "idx_device_observations_device_time" ON "" ("device_id", "observed_at");
CREATE INDEX "idx_device_observations_observed_at_brin" ON "" ("observed_at");
CREATE INDEX "idx_device_observations_mac_at" ON "" ("observed_mac_address", "observed_at");
CREATE INDEX "idx_device_observations_ip_at" ON "" ("observed_ip", "observed_at");
CREATE INDEX "idx_device_observations_source_at" ON "" ("observation_source", "observed_at");;

-- Data exporting was unselected.

-- Dumping structure for table public.device_policy_assignments
CREATE TABLE IF NOT EXISTS "device_policy_assignments" (
	"id" UUID NOT NULL DEFAULT gen_random_uuid(),
	"device_id" UUID NOT NULL,
	"policy_id" UUID NOT NULL,
	"assigned_by" TEXT NOT NULL DEFAULT 'system',
	"assigned_at" TIMESTAMPTZ NOT NULL DEFAULT now(),
	"is_active" BOOLEAN NOT NULL DEFAULT true,
	PRIMARY KEY ("id"),
	UNIQUE ("device_id", "policy_id"),
	CONSTRAINT "device_policy_assignments_device_id_fkey" FOREIGN KEY ("device_id") REFERENCES "devices" ("id") ON UPDATE NO ACTION ON DELETE CASCADE,
	CONSTRAINT "device_policy_assignments_policy_id_fkey" FOREIGN KEY ("policy_id") REFERENCES "policy_templates" ("id") ON UPDATE NO ACTION ON DELETE CASCADE
);

-- Data exporting was unselected.

-- Dumping structure for table public.device_response_overrides
CREATE TABLE IF NOT EXISTS "device_response_overrides" (
	"device_id" UUID NOT NULL,
	"auto_response_enabled" BOOLEAN NOT NULL DEFAULT true,
	"max_auto_action" TEXT NOT NULL DEFAULT 'internet_block',
	"preferred_action" TEXT NULL DEFAULT NULL,
	"suppress_until" TIMESTAMPTZ NULL DEFAULT NULL,
	"notes" TEXT NULL DEFAULT NULL,
	"updated_by" TEXT NOT NULL DEFAULT 'api',
	"created_at" TIMESTAMPTZ NOT NULL DEFAULT now(),
	"updated_at" TIMESTAMPTZ NOT NULL DEFAULT now(),
	"automation_enabled" BOOLEAN NULL DEFAULT NULL,
	"id" UUID NULL DEFAULT gen_random_uuid(),
	PRIMARY KEY ("device_id"),
	UNIQUE ("id"),
	UNIQUE ("device_id"),
	CONSTRAINT "device_response_overrides_device_id_fkey" FOREIGN KEY ("device_id") REFERENCES "devices" ("id") ON UPDATE NO ACTION ON DELETE CASCADE
)
CREATE INDEX "idx_device_response_overrides_suppress_until" ON "" ("suppress_until");
CREATE INDEX "idx_device_response_overrides_device" ON "" ("device_id");;

-- Data exporting was unselected.

-- Dumping structure for table public.device_traffic_samples
CREATE TABLE IF NOT EXISTS "device_traffic_samples" (
	"id" UUID NOT NULL DEFAULT gen_random_uuid(),
	"device_id" UUID NULL DEFAULT NULL,
	"sample_time" TIMESTAMPTZ NOT NULL DEFAULT now(),
	"source_system" TEXT NOT NULL DEFAULT 'opnsense_pf_states',
	"direction" TEXT NOT NULL DEFAULT 'unknown',
	"src_ip" INET NULL DEFAULT NULL,
	"src_port" INTEGER NULL DEFAULT NULL,
	"dest_ip" INET NULL DEFAULT NULL,
	"dest_port" INTEGER NULL DEFAULT NULL,
	"protocol" TEXT NULL DEFAULT NULL,
	"country_code" TEXT NULL DEFAULT NULL,
	"bytes_delta" BIGINT NOT NULL DEFAULT 0,
	"packets_delta" BIGINT NOT NULL DEFAULT 0,
	"connection_count" INTEGER NOT NULL DEFAULT 1,
	"state_key" TEXT NOT NULL,
	"raw_json" JSONB NOT NULL DEFAULT '{}',
	"created_at" TIMESTAMPTZ NOT NULL DEFAULT now(),
	PRIMARY KEY ("id"),
	CONSTRAINT "device_traffic_samples_device_id_fkey" FOREIGN KEY ("device_id") REFERENCES "devices" ("id") ON UPDATE NO ACTION ON DELETE SET NULL
)
CREATE INDEX "idx_device_traffic_samples_device_time" ON "" ("device_id", "sample_time");
CREATE INDEX "idx_device_traffic_samples_time" ON "" ("sample_time");
CREATE INDEX "idx_device_traffic_samples_src_ip_time" ON "" ("src_ip", "sample_time");
CREATE INDEX "idx_device_traffic_samples_dest_ip_time" ON "" ("dest_ip", "sample_time");
CREATE INDEX "idx_device_traffic_samples_country_time" ON "" ("country_code", "sample_time");
CREATE INDEX "idx_device_traffic_samples_direction_time" ON "" ("direction", "sample_time");
CREATE INDEX "idx_device_traffic_samples_raw_gin" ON "" ("raw_json");;

-- Data exporting was unselected.

-- Dumping structure for table public.device_vulnerability_matches
CREATE TABLE IF NOT EXISTS "device_vulnerability_matches" (
	"id" UUID NOT NULL DEFAULT gen_random_uuid(),
	"device_id" UUID NOT NULL,
	"cve_id" TEXT NOT NULL,
	"match_source" TEXT NOT NULL,
	"match_confidence" INTEGER NOT NULL DEFAULT 0,
	"matched_vendor" TEXT NULL DEFAULT NULL,
	"matched_model" TEXT NULL DEFAULT NULL,
	"matched_version" TEXT NULL DEFAULT NULL,
	"manual_cpe_override" TEXT NULL DEFAULT NULL,
	"recommended_action" TEXT NULL DEFAULT NULL,
	"is_kev" BOOLEAN NOT NULL DEFAULT false,
	"cvss_base_score" NUMERIC(3,1) NULL DEFAULT NULL,
	"cvss_severity" TEXT NULL DEFAULT NULL,
	"match_status" TEXT NOT NULL DEFAULT 'open',
	"evidence_json" JSONB NOT NULL DEFAULT '{}',
	"first_seen_at" TIMESTAMPTZ NOT NULL DEFAULT now(),
	"last_seen_at" TIMESTAMPTZ NOT NULL DEFAULT now(),
	"created_at" TIMESTAMPTZ NOT NULL DEFAULT now(),
	"updated_at" TIMESTAMPTZ NOT NULL DEFAULT now(),
	PRIMARY KEY ("id"),
	UNIQUE ("device_id", "cve_id", "match_source"),
	CONSTRAINT "device_vulnerability_matches_cve_id_fkey" FOREIGN KEY ("cve_id") REFERENCES "cve_catalog" ("cve_id") ON UPDATE NO ACTION ON DELETE CASCADE,
	CONSTRAINT "device_vulnerability_matches_device_id_fkey" FOREIGN KEY ("device_id") REFERENCES "devices" ("id") ON UPDATE NO ACTION ON DELETE CASCADE
)
CREATE INDEX "idx_device_vuln_matches_device_status" ON "" ("device_id", "match_status");
CREATE INDEX "idx_device_vuln_matches_kev" ON "" ("is_kev");
CREATE INDEX "idx_device_vuln_matches_cvss" ON "" ("cvss_base_score");
CREATE INDEX "idx_device_vuln_matches_cve" ON "" ("cve_id");;

-- Data exporting was unselected.

-- Dumping structure for table public.device_vulnerability_overrides
CREATE TABLE IF NOT EXISTS "device_vulnerability_overrides" (
	"device_id" UUID NOT NULL,
	"manual_cpe_23" TEXT NULL DEFAULT NULL,
	"search_terms" JSONB NOT NULL DEFAULT '[]',
	"notes" TEXT NULL DEFAULT NULL,
	"updated_by" TEXT NOT NULL DEFAULT 'system',
	"created_at" TIMESTAMPTZ NOT NULL DEFAULT now(),
	"updated_at" TIMESTAMPTZ NOT NULL DEFAULT now(),
	PRIMARY KEY ("device_id"),
	CONSTRAINT "device_vulnerability_overrides_device_id_fkey" FOREIGN KEY ("device_id") REFERENCES "devices" ("id") ON UPDATE NO ACTION ON DELETE CASCADE
);

-- Data exporting was unselected.

-- Dumping structure for table public.devices
CREATE TABLE IF NOT EXISTS "devices" (
	"id" UUID NOT NULL DEFAULT gen_random_uuid(),
	"device_key" TEXT NOT NULL,
	"mac_address" TEXT NULL DEFAULT NULL,
	"current_ip" INET NULL DEFAULT NULL,
	"hostname" TEXT NULL DEFAULT NULL,
	"vendor" TEXT NULL DEFAULT NULL,
	"model" TEXT NULL DEFAULT NULL,
	"category" TEXT NULL DEFAULT NULL,
	"firmware_version" TEXT NULL DEFAULT NULL,
	"first_seen_at" TIMESTAMPTZ NOT NULL DEFAULT now(),
	"last_seen_at" TIMESTAMPTZ NOT NULL DEFAULT now(),
	"status" TEXT NOT NULL DEFAULT 'unknown',
	"risk_score" INTEGER NOT NULL DEFAULT 0,
	"risk_level" TEXT NOT NULL DEFAULT 'unknown',
	"active_policy" TEXT NULL DEFAULT NULL,
	"source_of_truth" TEXT NOT NULL DEFAULT 'unknown',
	"notes" TEXT NULL DEFAULT NULL,
	"created_at" TIMESTAMPTZ NOT NULL DEFAULT now(),
	"updated_at" TIMESTAMPTZ NOT NULL DEFAULT now(),
	"is_online" BOOLEAN NOT NULL DEFAULT false,
	"last_seen_dhcp_at" TIMESTAMPTZ NULL DEFAULT NULL,
	"last_seen_arp_at" TIMESTAMPTZ NULL DEFAULT NULL,
	"last_seen_scan_at" TIMESTAMPTZ NULL DEFAULT NULL,
	"last_scan_at" TIMESTAMPTZ NULL DEFAULT NULL,
	"last_offline_at" TIMESTAMPTZ NULL DEFAULT NULL,
	"discovery_sources" JSONB NOT NULL DEFAULT '[]',
	"open_tcp_ports" JSONB NOT NULL DEFAULT '[]',
	"open_udp_ports" JSONB NOT NULL DEFAULT '[]',
	"vendor_source" TEXT NOT NULL DEFAULT 'unknown',
	"model_source" TEXT NOT NULL DEFAULT 'unknown',
	"category_source" TEXT NOT NULL DEFAULT 'unknown',
	"firmware_source" TEXT NOT NULL DEFAULT 'unknown',
	"classification_confidence" INTEGER NOT NULL DEFAULT 0,
	"classification_reason" TEXT NULL DEFAULT NULL,
	"manual_vendor" TEXT NULL DEFAULT NULL,
	"manual_model" TEXT NULL DEFAULT NULL,
	"manual_category" TEXT NULL DEFAULT NULL,
	"manual_firmware_version" TEXT NULL DEFAULT NULL,
	"hardware_version" TEXT NULL DEFAULT NULL,
	"serial_number" TEXT NULL DEFAULT NULL,
	"hardware_source" TEXT NOT NULL DEFAULT 'unknown',
	"serial_source" TEXT NOT NULL DEFAULT 'unknown',
	"hostname_source" TEXT NOT NULL DEFAULT 'unknown',
	"reverse_dns_name" TEXT NULL DEFAULT NULL,
	"manual_hardware_version" TEXT NULL DEFAULT NULL,
	"manual_serial_number" TEXT NULL DEFAULT NULL,
	"identity_confirmed" BOOLEAN NOT NULL DEFAULT false,
	"identity_confirmed_at" TIMESTAMPTZ NULL DEFAULT NULL,
	"vulnerability_count" INTEGER NOT NULL DEFAULT 0,
	"kev_count" INTEGER NOT NULL DEFAULT 0,
	"highest_cvss" NUMERIC(3,1) NULL DEFAULT NULL,
	"highest_severity" TEXT NOT NULL DEFAULT 'unknown',
	"vulnerability_recommendation" TEXT NULL DEFAULT NULL,
	"vulnerability_last_checked_at" TIMESTAMPTZ NULL DEFAULT NULL,
	"vulnerability_summary_json" JSONB NOT NULL DEFAULT '{}',
	"policy_source" TEXT NOT NULL DEFAULT 'none',
	"policy_suggested" TEXT NULL DEFAULT NULL,
	"policy_suggested_source" TEXT NULL DEFAULT NULL,
	"policy_effective_mode" TEXT NOT NULL DEFAULT 'normal',
	"policy_last_applied_at" TIMESTAMPTZ NULL DEFAULT NULL,
	"policy_effective_json" JSONB NOT NULL DEFAULT '{}',
	"is_whitelisted" BOOLEAN NOT NULL DEFAULT false,
	"is_blacklisted" BOOLEAN NOT NULL DEFAULT false,
	"geo_restrictions_enabled" BOOLEAN NOT NULL DEFAULT false,
	"upnp_blocked" BOOLEAN NOT NULL DEFAULT false,
	PRIMARY KEY ("id"),
	UNIQUE ("device_key"),
	UNIQUE ("mac_address")
)
CREATE INDEX "idx_devices_current_ip" ON "" ("current_ip");
CREATE INDEX "idx_devices_status" ON "" ("status");
CREATE INDEX "idx_devices_last_seen_at" ON "" ("last_seen_at");
CREATE INDEX "idx_devices_is_online" ON "" ("is_online");
CREATE INDEX "idx_devices_last_seen_dhcp_at" ON "" ("last_seen_dhcp_at");
CREATE INDEX "idx_devices_last_seen_arp_at" ON "" ("last_seen_arp_at");
CREATE INDEX "idx_devices_last_seen_scan_at" ON "" ("last_seen_scan_at");
CREATE INDEX "idx_devices_last_scan_at" ON "" ("last_scan_at");
CREATE INDEX "idx_devices_discovery_sources_gin" ON "" ("discovery_sources");
CREATE INDEX "idx_devices_vendor_source" ON "" ("vendor_source");
CREATE INDEX "idx_devices_model_source" ON "" ("model_source");
CREATE INDEX "idx_devices_category_source" ON "" ("category_source");
CREATE INDEX "idx_devices_firmware_source" ON "" ("firmware_source");
CREATE INDEX "idx_devices_category" ON "" ("category");
CREATE INDEX "idx_devices_vendor" ON "" ("vendor");
CREATE INDEX "idx_devices_model" ON "" ("model");
CREATE INDEX "idx_devices_classification_confidence" ON "" ("classification_confidence");
CREATE INDEX "idx_devices_hardware_version" ON "" ("hardware_version");
CREATE INDEX "idx_devices_serial_number" ON "" ("serial_number");
CREATE INDEX "idx_devices_hardware_source" ON "" ("hardware_source");
CREATE INDEX "idx_devices_serial_source" ON "" ("serial_source");
CREATE INDEX "idx_devices_hostname_source" ON "" ("hostname_source");
CREATE INDEX "idx_devices_reverse_dns_name" ON "" ("reverse_dns_name");
CREATE INDEX "idx_devices_identity_confirmed" ON "" ("identity_confirmed");
CREATE INDEX "idx_devices_policy_source" ON "" ("policy_source");
CREATE INDEX "idx_devices_policy_suggested" ON "" ("policy_suggested");
CREATE INDEX "idx_devices_policy_effective_mode" ON "" ("policy_effective_mode");
CREATE INDEX "idx_devices_is_whitelisted" ON "" ("is_whitelisted");
CREATE INDEX "idx_devices_is_blacklisted" ON "" ("is_blacklisted");
CREATE INDEX "idx_devices_geo_restrictions_enabled" ON "" ("geo_restrictions_enabled");
CREATE INDEX "idx_devices_upnp_blocked" ON "" ("upnp_blocked");;

-- Data exporting was unselected.

-- Dumping structure for function public.digest
DELIMITER //
CREATE FUNCTION "digest"() RETURNS BYTEA AS $$ pg_digest $$//
DELIMITER ;

-- Dumping structure for function public.digest
DELIMITER //
CREATE FUNCTION "digest"() RETURNS BYTEA AS $$ pg_digest $$//
DELIMITER ;

-- Dumping structure for function public.encrypt
DELIMITER //
CREATE FUNCTION "encrypt"() RETURNS BYTEA AS $$ pg_encrypt $$//
DELIMITER ;

-- Dumping structure for function public.encrypt_iv
DELIMITER //
CREATE FUNCTION "encrypt_iv"() RETURNS BYTEA AS $$ pg_encrypt_iv $$//
DELIMITER ;

-- Dumping structure for function public.gen_random_bytes
DELIMITER //
CREATE FUNCTION "gen_random_bytes"() RETURNS BYTEA AS $$ pg_random_bytes $$//
DELIMITER ;

-- Dumping structure for function public.gen_random_uuid
DELIMITER //
CREATE FUNCTION "gen_random_uuid"() RETURNS UUID AS $$ pg_random_uuid $$//
DELIMITER ;

-- Dumping structure for function public.gen_salt
DELIMITER //
CREATE FUNCTION "gen_salt"() RETURNS TEXT AS $$ pg_gen_salt_rounds $$//
DELIMITER ;

-- Dumping structure for function public.gen_salt
DELIMITER //
CREATE FUNCTION "gen_salt"() RETURNS TEXT AS $$ pg_gen_salt $$//
DELIMITER ;

-- Dumping structure for table public.generated_reports
CREATE TABLE IF NOT EXISTS "generated_reports" (
	"id" UUID NOT NULL DEFAULT gen_random_uuid(),
	"report_type" TEXT NOT NULL DEFAULT 'weekly',
	"report_format" TEXT NOT NULL DEFAULT 'html',
	"period_start" TIMESTAMPTZ NOT NULL,
	"period_end" TIMESTAMPTZ NOT NULL,
	"title" TEXT NOT NULL,
	"file_path" TEXT NOT NULL,
	"file_size_bytes" BIGINT NULL DEFAULT NULL,
	"sha256" TEXT NULL DEFAULT NULL,
	"status" TEXT NOT NULL DEFAULT 'generated',
	"error_message" TEXT NULL DEFAULT NULL,
	"generated_by" TEXT NOT NULL DEFAULT 'report-engine',
	"created_at" TIMESTAMPTZ NOT NULL DEFAULT now(),
	PRIMARY KEY ("id")
)
CREATE INDEX "idx_generated_reports_created" ON "" ("created_at");
CREATE INDEX "idx_generated_reports_type" ON "" ("report_type", "report_format");
CREATE INDEX "idx_generated_reports_period" ON "" ("period_start", "period_end");;

-- Data exporting was unselected.

-- Dumping structure for function public.gin_extract_query_trgm
DELIMITER //
CREATE FUNCTION "gin_extract_query_trgm"() RETURNS UNKNOWN AS $$ gin_extract_query_trgm $$//
DELIMITER ;

-- Dumping structure for function public.gin_extract_value_trgm
DELIMITER //
CREATE FUNCTION "gin_extract_value_trgm"() RETURNS UNKNOWN AS $$ gin_extract_value_trgm $$//
DELIMITER ;

-- Dumping structure for function public.gin_trgm_consistent
DELIMITER //
CREATE FUNCTION "gin_trgm_consistent"() RETURNS BOOLEAN AS $$ gin_trgm_consistent $$//
DELIMITER ;

-- Dumping structure for function public.gin_trgm_triconsistent
DELIMITER //
CREATE FUNCTION "gin_trgm_triconsistent"() RETURNS CHAR AS $$ gin_trgm_triconsistent $$//
DELIMITER ;

-- Dumping structure for function public.gtrgm_compress
DELIMITER //
CREATE FUNCTION "gtrgm_compress"() RETURNS UNKNOWN AS $$ gtrgm_compress $$//
DELIMITER ;

-- Dumping structure for function public.gtrgm_consistent
DELIMITER //
CREATE FUNCTION "gtrgm_consistent"() RETURNS BOOLEAN AS $$ gtrgm_consistent $$//
DELIMITER ;

-- Dumping structure for function public.gtrgm_decompress
DELIMITER //
CREATE FUNCTION "gtrgm_decompress"() RETURNS UNKNOWN AS $$ gtrgm_decompress $$//
DELIMITER ;

-- Dumping structure for function public.gtrgm_distance
DELIMITER //
CREATE FUNCTION "gtrgm_distance"() RETURNS DOUBLE PRECISION AS $$ gtrgm_distance $$//
DELIMITER ;

-- Dumping structure for function public.gtrgm_in
DELIMITER //
CREATE FUNCTION "gtrgm_in"() RETURNS UNKNOWN AS $$ gtrgm_in $$//
DELIMITER ;

-- Dumping structure for function public.gtrgm_options
DELIMITER //
CREATE FUNCTION "gtrgm_options"() RETURNS UNKNOWN AS $$ gtrgm_options $$//
DELIMITER ;

-- Dumping structure for function public.gtrgm_out
DELIMITER //
CREATE FUNCTION "gtrgm_out"() RETURNS UNKNOWN AS $$ gtrgm_out $$//
DELIMITER ;

-- Dumping structure for function public.gtrgm_penalty
DELIMITER //
CREATE FUNCTION "gtrgm_penalty"() RETURNS UNKNOWN AS $$ gtrgm_penalty $$//
DELIMITER ;

-- Dumping structure for function public.gtrgm_picksplit
DELIMITER //
CREATE FUNCTION "gtrgm_picksplit"() RETURNS UNKNOWN AS $$ gtrgm_picksplit $$//
DELIMITER ;

-- Dumping structure for function public.gtrgm_same
DELIMITER //
CREATE FUNCTION "gtrgm_same"() RETURNS UNKNOWN AS $$ gtrgm_same $$//
DELIMITER ;

-- Dumping structure for function public.gtrgm_union
DELIMITER //
CREATE FUNCTION "gtrgm_union"() RETURNS UNKNOWN AS $$ gtrgm_union $$//
DELIMITER ;

-- Dumping structure for function public.hmac
DELIMITER //
CREATE FUNCTION "hmac"() RETURNS BYTEA AS $$ pg_hmac $$//
DELIMITER ;

-- Dumping structure for function public.hmac
DELIMITER //
CREATE FUNCTION "hmac"() RETURNS BYTEA AS $$ pg_hmac $$//
DELIMITER ;

-- Dumping structure for table public.incidents
CREATE TABLE IF NOT EXISTS "incidents" (
	"id" UUID NOT NULL DEFAULT gen_random_uuid(),
	"device_id" UUID NULL DEFAULT NULL,
	"incident_type" TEXT NOT NULL,
	"severity" TEXT NOT NULL,
	"source_system" TEXT NOT NULL,
	"title" TEXT NOT NULL,
	"description" TEXT NULL DEFAULT NULL,
	"evidence_json" JSONB NOT NULL DEFAULT '{}',
	"status" TEXT NOT NULL DEFAULT 'open',
	"created_at" TIMESTAMPTZ NOT NULL DEFAULT now(),
	"closed_at" TIMESTAMPTZ NULL DEFAULT NULL,
	"updated_at" TIMESTAMPTZ NOT NULL DEFAULT now(),
	"first_seen_at" TIMESTAMPTZ NULL DEFAULT NULL,
	"last_seen_at" TIMESTAMPTZ NULL DEFAULT NULL,
	"event_count" INTEGER NOT NULL DEFAULT 1,
	"dedupe_key" TEXT NULL DEFAULT NULL,
	PRIMARY KEY ("id"),
	UNIQUE ("dedupe_key"),
	CONSTRAINT "incidents_device_id_fkey" FOREIGN KEY ("device_id") REFERENCES "devices" ("id") ON UPDATE NO ACTION ON DELETE SET NULL
)
CREATE INDEX "idx_incidents_device_id" ON "" ("device_id");
CREATE INDEX "idx_incidents_status" ON "" ("status");
CREATE INDEX "idx_incidents_severity" ON "" ("severity");
CREATE INDEX "idx_incidents_created_at" ON "" ("created_at");
CREATE INDEX "idx_incidents_updated_at" ON "" ("updated_at");
CREATE INDEX "idx_incidents_last_seen_at" ON "" ("last_seen_at");
CREATE INDEX "idx_incidents_dedupe_key" ON "" ("dedupe_key");;

-- Data exporting was unselected.

-- Dumping structure for table public.notification_deliveries
CREATE TABLE IF NOT EXISTS "notification_deliveries" (
	"id" UUID NOT NULL DEFAULT gen_random_uuid(),
	"rule_name" TEXT NOT NULL,
	"channel" TEXT NOT NULL,
	"status" TEXT NOT NULL DEFAULT 'pending',
	"dedupe_key" TEXT NOT NULL,
	"incident_id" UUID NULL DEFAULT NULL,
	"device_id" UUID NULL DEFAULT NULL,
	"message_title" TEXT NOT NULL,
	"message_body" TEXT NOT NULL,
	"response_json" JSONB NOT NULL DEFAULT '{}',
	"error_message" TEXT NULL DEFAULT NULL,
	"sent_at" TIMESTAMPTZ NULL DEFAULT NULL,
	"created_at" TIMESTAMPTZ NOT NULL DEFAULT now(),
	PRIMARY KEY ("id"),
	UNIQUE ("dedupe_key"),
	CONSTRAINT "notification_deliveries_device_id_fkey" FOREIGN KEY ("device_id") REFERENCES "devices" ("id") ON UPDATE NO ACTION ON DELETE SET NULL,
	CONSTRAINT "notification_deliveries_incident_id_fkey" FOREIGN KEY ("incident_id") REFERENCES "incidents" ("id") ON UPDATE NO ACTION ON DELETE SET NULL
);
CREATE INDEX "idx_notification_deliveries_incident" ON "" ("incident_id");
CREATE INDEX "idx_notification_deliveries_device" ON "" ("device_id");
CREATE INDEX "idx_notification_deliveries_created" ON "" ("created_at");
CREATE INDEX "idx_notification_deliveries_status" ON "" ("status");
CREATE INDEX "idx_notification_deliveries_channel" ON "" ("channel");;

-- Data exporting was unselected.

-- Dumping structure for table public.notification_rules
CREATE TABLE IF NOT EXISTS "notification_rules" (
	"id" UUID NOT NULL DEFAULT gen_random_uuid(),
	"rule_name" TEXT NOT NULL,
	"is_enabled" BOOLEAN NOT NULL DEFAULT true,
	"min_severity" TEXT NOT NULL DEFAULT 'high',
	"event_types" JSONB NOT NULL DEFAULT '[]',
	"channels" JSONB NOT NULL DEFAULT '["ha_persistent"]',
	"cooldown_minutes" INTEGER NOT NULL DEFAULT 60,
	"created_at" TIMESTAMPTZ NOT NULL DEFAULT now(),
	"updated_at" TIMESTAMPTZ NOT NULL DEFAULT now(),
	PRIMARY KEY ("id"),
	UNIQUE ("rule_name")
)
CREATE INDEX "idx_notification_rules_enabled" ON "" ("is_enabled");;

-- Data exporting was unselected.

-- Dumping structure for table public.packet_captures
CREATE TABLE IF NOT EXISTS "packet_captures" (
	"id" UUID NOT NULL DEFAULT gen_random_uuid(),
	"incident_id" UUID NULL DEFAULT NULL,
	"device_id" UUID NULL DEFAULT NULL,
	"device_ip" INET NOT NULL,
	"interface_name" TEXT NOT NULL,
	"bpf_filter" TEXT NOT NULL,
	"status" TEXT NOT NULL DEFAULT 'created',
	"pid" INTEGER NULL DEFAULT NULL,
	"command_json" JSONB NOT NULL DEFAULT '[]',
	"file_path" TEXT NULL DEFAULT NULL,
	"file_size_bytes" BIGINT NULL DEFAULT NULL,
	"sha256" TEXT NULL DEFAULT NULL,
	"started_at" TIMESTAMPTZ NULL DEFAULT NULL,
	"stopped_at" TIMESTAMPTZ NULL DEFAULT NULL,
	"duration_seconds" INTEGER NOT NULL DEFAULT 120,
	"max_file_mb" INTEGER NOT NULL DEFAULT 50,
	"error_message" TEXT NULL DEFAULT NULL,
	"created_by" TEXT NOT NULL DEFAULT 'manual',
	"created_at" TIMESTAMPTZ NOT NULL DEFAULT now(),
	"updated_at" TIMESTAMPTZ NOT NULL DEFAULT now(),
	PRIMARY KEY ("id"),
	CONSTRAINT "packet_captures_device_id_fkey" FOREIGN KEY ("device_id") REFERENCES "devices" ("id") ON UPDATE NO ACTION ON DELETE SET NULL,
	CONSTRAINT "packet_captures_incident_id_fkey" FOREIGN KEY ("incident_id") REFERENCES "incidents" ("id") ON UPDATE NO ACTION ON DELETE SET NULL
)
CREATE INDEX "idx_packet_captures_created" ON "" ("created_at");
CREATE INDEX "idx_packet_captures_status" ON "" ("status");
CREATE INDEX "idx_packet_captures_incident" ON "" ("incident_id");
CREATE INDEX "idx_packet_captures_device" ON "" ("device_id");
CREATE INDEX "idx_packet_captures_ip" ON "" ("device_ip");;

-- Data exporting was unselected.

-- Dumping structure for function public.pgp_armor_headers
DELIMITER //
CREATE FUNCTION "pgp_armor_headers"("" TEXT, key , value ) RETURNS UNKNOWN AS $$ pgp_armor_headers $$//
DELIMITER ;

-- Dumping structure for function public.pgp_key_id
DELIMITER //
CREATE FUNCTION "pgp_key_id"() RETURNS TEXT AS $$ pgp_key_id_w $$//
DELIMITER ;

-- Dumping structure for function public.pgp_pub_decrypt
DELIMITER //
CREATE FUNCTION "pgp_pub_decrypt"() RETURNS TEXT AS $$ pgp_pub_decrypt_text $$//
DELIMITER ;

-- Dumping structure for function public.pgp_pub_decrypt
DELIMITER //
CREATE FUNCTION "pgp_pub_decrypt"() RETURNS TEXT AS $$ pgp_pub_decrypt_text $$//
DELIMITER ;

-- Dumping structure for function public.pgp_pub_decrypt
DELIMITER //
CREATE FUNCTION "pgp_pub_decrypt"() RETURNS TEXT AS $$ pgp_pub_decrypt_text $$//
DELIMITER ;

-- Dumping structure for function public.pgp_pub_decrypt_bytea
DELIMITER //
CREATE FUNCTION "pgp_pub_decrypt_bytea"() RETURNS BYTEA AS $$ pgp_pub_decrypt_bytea $$//
DELIMITER ;

-- Dumping structure for function public.pgp_pub_decrypt_bytea
DELIMITER //
CREATE FUNCTION "pgp_pub_decrypt_bytea"() RETURNS BYTEA AS $$ pgp_pub_decrypt_bytea $$//
DELIMITER ;

-- Dumping structure for function public.pgp_pub_decrypt_bytea
DELIMITER //
CREATE FUNCTION "pgp_pub_decrypt_bytea"() RETURNS BYTEA AS $$ pgp_pub_decrypt_bytea $$//
DELIMITER ;

-- Dumping structure for function public.pgp_pub_encrypt
DELIMITER //
CREATE FUNCTION "pgp_pub_encrypt"() RETURNS BYTEA AS $$ pgp_pub_encrypt_text $$//
DELIMITER ;

-- Dumping structure for function public.pgp_pub_encrypt
DELIMITER //
CREATE FUNCTION "pgp_pub_encrypt"() RETURNS BYTEA AS $$ pgp_pub_encrypt_text $$//
DELIMITER ;

-- Dumping structure for function public.pgp_pub_encrypt_bytea
DELIMITER //
CREATE FUNCTION "pgp_pub_encrypt_bytea"() RETURNS BYTEA AS $$ pgp_pub_encrypt_bytea $$//
DELIMITER ;

-- Dumping structure for function public.pgp_pub_encrypt_bytea
DELIMITER //
CREATE FUNCTION "pgp_pub_encrypt_bytea"() RETURNS BYTEA AS $$ pgp_pub_encrypt_bytea $$//
DELIMITER ;

-- Dumping structure for function public.pgp_sym_decrypt
DELIMITER //
CREATE FUNCTION "pgp_sym_decrypt"() RETURNS TEXT AS $$ pgp_sym_decrypt_text $$//
DELIMITER ;

-- Dumping structure for function public.pgp_sym_decrypt
DELIMITER //
CREATE FUNCTION "pgp_sym_decrypt"() RETURNS TEXT AS $$ pgp_sym_decrypt_text $$//
DELIMITER ;

-- Dumping structure for function public.pgp_sym_decrypt_bytea
DELIMITER //
CREATE FUNCTION "pgp_sym_decrypt_bytea"() RETURNS BYTEA AS $$ pgp_sym_decrypt_bytea $$//
DELIMITER ;

-- Dumping structure for function public.pgp_sym_decrypt_bytea
DELIMITER //
CREATE FUNCTION "pgp_sym_decrypt_bytea"() RETURNS BYTEA AS $$ pgp_sym_decrypt_bytea $$//
DELIMITER ;

-- Dumping structure for function public.pgp_sym_encrypt
DELIMITER //
CREATE FUNCTION "pgp_sym_encrypt"() RETURNS BYTEA AS $$ pgp_sym_encrypt_text $$//
DELIMITER ;

-- Dumping structure for function public.pgp_sym_encrypt
DELIMITER //
CREATE FUNCTION "pgp_sym_encrypt"() RETURNS BYTEA AS $$ pgp_sym_encrypt_text $$//
DELIMITER ;

-- Dumping structure for function public.pgp_sym_encrypt_bytea
DELIMITER //
CREATE FUNCTION "pgp_sym_encrypt_bytea"() RETURNS BYTEA AS $$ pgp_sym_encrypt_bytea $$//
DELIMITER ;

-- Dumping structure for function public.pgp_sym_encrypt_bytea
DELIMITER //
CREATE FUNCTION "pgp_sym_encrypt_bytea"() RETURNS BYTEA AS $$ pgp_sym_encrypt_bytea $$//
DELIMITER ;

-- Dumping structure for table public.phase7_ui_state
CREATE TABLE IF NOT EXISTS "phase7_ui_state" (
	"selection_type" TEXT NOT NULL,
	"object_id" TEXT NULL DEFAULT NULL,
	"label" TEXT NULL DEFAULT NULL,
	"updated_by" TEXT NOT NULL DEFAULT 'api',
	"updated_at" TIMESTAMPTZ NOT NULL DEFAULT now(),
	"details_json" JSONB NOT NULL DEFAULT '{}',
	PRIMARY KEY ("selection_type")
);

-- Data exporting was unselected.

-- Dumping structure for table public.policy_alias_managed_entries
CREATE TABLE IF NOT EXISTS "policy_alias_managed_entries" (
	"alias_name" TEXT NOT NULL,
	"address" INET NOT NULL,
	PRIMARY KEY ("alias_name", "address")
)
CREATE INDEX "idx_policy_alias_managed_entries_alias_name" ON "" ("alias_name");;

-- Data exporting was unselected.

-- Dumping structure for table public.policy_templates
CREATE TABLE IF NOT EXISTS "policy_templates" (
	"id" UUID NOT NULL DEFAULT gen_random_uuid(),
	"policy_name" TEXT NOT NULL,
	"policy_scope" TEXT NOT NULL DEFAULT 'device_category',
	"is_enabled" BOOLEAN NOT NULL DEFAULT true,
	"policy_json" JSONB NOT NULL DEFAULT '{}',
	"created_at" TIMESTAMPTZ NOT NULL DEFAULT now(),
	"updated_at" TIMESTAMPTZ NOT NULL DEFAULT now(),
	PRIMARY KEY ("id"),
	UNIQUE ("policy_name")
);

-- Data exporting was unselected.

-- Dumping structure for table public.response_action_events
CREATE TABLE IF NOT EXISTS "response_action_events" (
	"id" UUID NOT NULL DEFAULT gen_random_uuid(),
	"response_action_id" UUID NULL DEFAULT NULL,
	"incident_id" UUID NULL DEFAULT NULL,
	"device_id" UUID NULL DEFAULT NULL,
	"event_type" TEXT NOT NULL,
	"actor" TEXT NOT NULL DEFAULT 'response-engine',
	"message" TEXT NULL DEFAULT NULL,
	"details_json" JSONB NOT NULL DEFAULT '{}',
	"created_at" TIMESTAMPTZ NOT NULL DEFAULT now(),
	PRIMARY KEY ("id"),
	CONSTRAINT "response_action_events_device_id_fkey" FOREIGN KEY ("device_id") REFERENCES "devices" ("id") ON UPDATE NO ACTION ON DELETE SET NULL,
	CONSTRAINT "response_action_events_incident_id_fkey" FOREIGN KEY ("incident_id") REFERENCES "incidents" ("id") ON UPDATE NO ACTION ON DELETE SET NULL,
	CONSTRAINT "response_action_events_response_action_id_fkey" FOREIGN KEY ("response_action_id") REFERENCES "response_actions" ("id") ON UPDATE NO ACTION ON DELETE CASCADE
)
CREATE INDEX "idx_response_action_events_action" ON "" ("response_action_id", "created_at");
CREATE INDEX "idx_response_action_events_incident" ON "" ("incident_id", "created_at");;

-- Data exporting was unselected.

-- Dumping structure for table public.response_actions
CREATE TABLE IF NOT EXISTS "response_actions" (
	"id" UUID NOT NULL DEFAULT gen_random_uuid(),
	"incident_id" UUID NULL DEFAULT NULL,
	"device_id" UUID NULL DEFAULT NULL,
	"action_type" TEXT NOT NULL,
	"action_mode" TEXT NOT NULL DEFAULT 'manual',
	"status" TEXT NOT NULL DEFAULT 'suggested',
	"severity" TEXT NULL DEFAULT NULL,
	"source_system" TEXT NULL DEFAULT NULL,
	"incident_type" TEXT NULL DEFAULT NULL,
	"requested_by" TEXT NOT NULL DEFAULT 'response-engine',
	"approved_by" TEXT NULL DEFAULT NULL,
	"applied_by" TEXT NULL DEFAULT NULL,
	"rollback_by" TEXT NULL DEFAULT NULL,
	"reason" TEXT NULL DEFAULT NULL,
	"ttl_minutes" INTEGER NOT NULL DEFAULT 60,
	"expires_at" TIMESTAMPTZ NULL DEFAULT NULL,
	"suggested_at" TIMESTAMPTZ NOT NULL DEFAULT now(),
	"approved_at" TIMESTAMPTZ NULL DEFAULT NULL,
	"applied_at" TIMESTAMPTZ NULL DEFAULT NULL,
	"rollback_requested_at" TIMESTAMPTZ NULL DEFAULT NULL,
	"rolled_back_at" TIMESTAMPTZ NULL DEFAULT NULL,
	"last_attempt_at" TIMESTAMPTZ NULL DEFAULT NULL,
	"previous_state_json" JSONB NOT NULL DEFAULT '{}',
	"params_json" JSONB NOT NULL DEFAULT '{}',
	"simulation_json" JSONB NOT NULL DEFAULT '{}',
	"result_json" JSONB NOT NULL DEFAULT '{}',
	"created_at" TIMESTAMPTZ NOT NULL DEFAULT now(),
	"updated_at" TIMESTAMPTZ NOT NULL DEFAULT now(),
	"mode" TEXT NULL DEFAULT NULL,
	"rollback_reason" TEXT NULL DEFAULT NULL,
	"actor" TEXT NULL DEFAULT NULL,
	"created_by" TEXT NULL DEFAULT NULL,
	PRIMARY KEY ("id"),
	UNIQUE ("incident_id", "action_type"),
	CONSTRAINT "response_actions_device_id_fkey" FOREIGN KEY ("device_id") REFERENCES "devices" ("id") ON UPDATE NO ACTION ON DELETE SET NULL,
	CONSTRAINT "response_actions_incident_id_fkey" FOREIGN KEY ("incident_id") REFERENCES "incidents" ("id") ON UPDATE NO ACTION ON DELETE SET NULL
)
CREATE INDEX "idx_response_actions_incident" ON "" ("incident_id");
CREATE INDEX "idx_response_actions_device" ON "" ("device_id");
CREATE INDEX "idx_response_actions_status" ON "" ("status");
CREATE INDEX "idx_response_actions_action_type" ON "" ("action_type");
CREATE INDEX "idx_response_actions_expires" ON "" ("expires_at");
CREATE INDEX "idx_response_actions_active" ON "" ("status", "expires_at");
CREATE INDEX "idx_response_actions_updated" ON "" ("updated_at");
CREATE INDEX "idx_response_actions_active_incident" ON "" ("incident_id", "status", "action_type");;

-- Data exporting was unselected.

-- Dumping structure for table public.response_ignores
CREATE TABLE IF NOT EXISTS "response_ignores" (
	"id" UUID NOT NULL DEFAULT gen_random_uuid(),
	"is_enabled" BOOLEAN NOT NULL DEFAULT true,
	"incident_id" UUID NULL DEFAULT NULL,
	"device_id" UUID NOT NULL,
	"incident_type" TEXT NOT NULL,
	"source_system" TEXT NULL DEFAULT NULL,
	"reason" TEXT NULL DEFAULT NULL,
	"created_by" TEXT NOT NULL DEFAULT 'api',
	"expires_at" TIMESTAMPTZ NULL DEFAULT NULL,
	"created_at" TIMESTAMPTZ NOT NULL DEFAULT now(),
	"updated_at" TIMESTAMPTZ NOT NULL DEFAULT now(),
	PRIMARY KEY ("id"),
	CONSTRAINT "response_ignores_device_id_fkey" FOREIGN KEY ("device_id") REFERENCES "devices" ("id") ON UPDATE NO ACTION ON DELETE CASCADE,
	CONSTRAINT "response_ignores_incident_id_fkey" FOREIGN KEY ("incident_id") REFERENCES "incidents" ("id") ON UPDATE NO ACTION ON DELETE SET NULL
)
CREATE INDEX "idx_response_ignores_active_pattern" ON "" ("is_enabled", "device_id", "incident_type", "source_system", "expires_at");
CREATE INDEX "idx_response_ignores_incident" ON "" ("incident_id");;

-- Data exporting was unselected.

-- Dumping structure for table public.response_playbooks
CREATE TABLE IF NOT EXISTS "response_playbooks" (
	"id" UUID NOT NULL DEFAULT gen_random_uuid(),
	"playbook_name" TEXT NOT NULL,
	"is_enabled" BOOLEAN NOT NULL DEFAULT true,
	"priority" INTEGER NOT NULL DEFAULT 100,
	"source_system" TEXT NULL DEFAULT NULL,
	"incident_type" TEXT NULL DEFAULT NULL,
	"min_severity" TEXT NOT NULL DEFAULT 'medium',
	"action_type" TEXT NOT NULL,
	"auto_allowed" BOOLEAN NOT NULL DEFAULT false,
	"ttl_minutes" INTEGER NOT NULL DEFAULT 60,
	"cooldown_minutes" INTEGER NOT NULL DEFAULT 60,
	"require_device" BOOLEAN NOT NULL DEFAULT true,
	"require_lan_device" BOOLEAN NOT NULL DEFAULT true,
	"require_dest_ip" BOOLEAN NOT NULL DEFAULT false,
	"conditions_json" JSONB NOT NULL DEFAULT '{}',
	"description" TEXT NULL DEFAULT NULL,
	"created_at" TIMESTAMPTZ NOT NULL DEFAULT now(),
	"updated_at" TIMESTAMPTZ NOT NULL DEFAULT now(),
	"display_name" TEXT NULL DEFAULT NULL,
	PRIMARY KEY ("id"),
	UNIQUE ("playbook_name")
)
CREATE INDEX "idx_response_playbooks_enabled_priority" ON "" ("is_enabled", "priority");
CREATE INDEX "idx_response_playbooks_type" ON "" ("incident_type");
CREATE INDEX "idx_response_playbooks_source" ON "" ("source_system");;

-- Data exporting was unselected.

-- Dumping structure for table public.response_settings
CREATE TABLE IF NOT EXISTS "response_settings" (
	"setting_key" TEXT NOT NULL,
	"setting_value" JSONB NOT NULL DEFAULT 'null',
	"description" TEXT NULL DEFAULT NULL,
	"updated_by" TEXT NOT NULL DEFAULT 'system',
	"created_at" TIMESTAMPTZ NOT NULL DEFAULT now(),
	"updated_at" TIMESTAMPTZ NOT NULL DEFAULT now(),
	PRIMARY KEY ("setting_key")
);

-- Data exporting was unselected.

-- Dumping structure for table public.response_suppressions
CREATE TABLE IF NOT EXISTS "response_suppressions" (
	"id" UUID NOT NULL DEFAULT gen_random_uuid(),
	"is_enabled" BOOLEAN NOT NULL DEFAULT true,
	"scope" TEXT NOT NULL DEFAULT 'incident_pattern',
	"device_id" UUID NULL DEFAULT NULL,
	"incident_type" TEXT NULL DEFAULT NULL,
	"source_system" TEXT NULL DEFAULT NULL,
	"severity" TEXT NULL DEFAULT NULL,
	"domain" TEXT NULL DEFAULT NULL,
	"country_code" TEXT NULL DEFAULT NULL,
	"signature_id" TEXT NULL DEFAULT NULL,
	"signature_name" TEXT NULL DEFAULT NULL,
	"title_pattern" TEXT NULL DEFAULT NULL,
	"reason" TEXT NULL DEFAULT NULL,
	"created_by" TEXT NOT NULL DEFAULT 'api',
	"expires_at" TIMESTAMPTZ NULL DEFAULT NULL,
	"created_at" TIMESTAMPTZ NOT NULL DEFAULT now(),
	"updated_at" TIMESTAMPTZ NOT NULL DEFAULT now(),
	"device_ip" INET NULL DEFAULT NULL,
	PRIMARY KEY ("id"),
	CONSTRAINT "response_suppressions_device_id_fkey" FOREIGN KEY ("device_id") REFERENCES "devices" ("id") ON UPDATE NO ACTION ON DELETE CASCADE
)
CREATE INDEX "idx_response_suppressions_enabled" ON "" ("is_enabled");
CREATE INDEX "idx_response_suppressions_device" ON "" ("device_id");
CREATE INDEX "idx_response_suppressions_expires" ON "" ("expires_at");
CREATE INDEX "idx_response_suppressions_type_source" ON "" ("incident_type", "source_system");
CREATE INDEX "idx_response_suppressions_active" ON "" ("is_enabled", "expires_at");
CREATE INDEX "idx_response_suppressions_active_pattern" ON "" ("is_enabled", "device_id", "incident_type", "source_system", "expires_at");;

-- Data exporting was unselected.

-- Dumping structure for table public.security_events
CREATE TABLE IF NOT EXISTS "security_events" (
	"id" UUID NOT NULL DEFAULT gen_random_uuid(),
	"incident_id" UUID NULL DEFAULT NULL,
	"device_id" UUID NULL DEFAULT NULL,
	"source_system" TEXT NOT NULL,
	"event_type" TEXT NOT NULL,
	"severity" TEXT NOT NULL DEFAULT 'low',
	"title" TEXT NOT NULL,
	"description" TEXT NULL DEFAULT NULL,
	"src_ip" INET NULL DEFAULT NULL,
	"src_port" INTEGER NULL DEFAULT NULL,
	"dest_ip" INET NULL DEFAULT NULL,
	"dest_port" INTEGER NULL DEFAULT NULL,
	"protocol" TEXT NULL DEFAULT NULL,
	"domain" TEXT NULL DEFAULT NULL,
	"country_code" TEXT NULL DEFAULT NULL,
	"signature_id" TEXT NULL DEFAULT NULL,
	"signature_name" TEXT NULL DEFAULT NULL,
	"dedupe_key" TEXT NULL DEFAULT NULL,
	"event_time" TIMESTAMPTZ NOT NULL DEFAULT now(),
	"raw_json" JSONB NOT NULL DEFAULT '{}',
	"created_at" TIMESTAMPTZ NOT NULL DEFAULT now(),
	PRIMARY KEY ("id"),
	CONSTRAINT "security_events_device_id_fkey" FOREIGN KEY ("device_id") REFERENCES "devices" ("id") ON UPDATE NO ACTION ON DELETE SET NULL,
	CONSTRAINT "security_events_incident_id_fkey" FOREIGN KEY ("incident_id") REFERENCES "incidents" ("id") ON UPDATE NO ACTION ON DELETE SET NULL
)
CREATE INDEX "idx_security_events_incident_id" ON "" ("incident_id");
CREATE INDEX "idx_security_events_device_id" ON "" ("device_id");
CREATE INDEX "idx_security_events_source_time" ON "" ("source_system", "event_time");
CREATE INDEX "idx_security_events_type_time" ON "" ("event_type", "event_time");
CREATE INDEX "idx_security_events_severity_time" ON "" ("severity", "event_time");
CREATE INDEX "idx_security_events_event_time_brin" ON "" ("event_time");
CREATE INDEX "idx_security_events_src_ip_time" ON "" ("src_ip", "event_time");
CREATE INDEX "idx_security_events_dest_ip_time" ON "" ("dest_ip", "event_time");
CREATE INDEX "idx_security_events_domain_time" ON "" ("domain", "event_time");
CREATE INDEX "idx_security_events_dedupe_key" ON "" ("dedupe_key");;

-- Data exporting was unselected.

-- Dumping structure for function public.set_limit
DELIMITER //
CREATE FUNCTION "set_limit"() RETURNS REAL AS $$ set_limit $$//
DELIMITER ;

-- Dumping structure for function public.set_updated_at
DELIMITER //
CREATE FUNCTION "set_updated_at"() RETURNS UNKNOWN AS $$ 
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
 $$//
DELIMITER ;

-- Dumping structure for function public.show_limit
DELIMITER //
CREATE FUNCTION "show_limit"() RETURNS REAL AS $$ show_limit $$//
DELIMITER ;

-- Dumping structure for function public.show_trgm
DELIMITER //
CREATE FUNCTION "show_trgm"() RETURNS UNKNOWN AS $$ show_trgm $$//
DELIMITER ;

-- Dumping structure for function public.similarity
DELIMITER //
CREATE FUNCTION "similarity"() RETURNS REAL AS $$ similarity $$//
DELIMITER ;

-- Dumping structure for function public.similarity_dist
DELIMITER //
CREATE FUNCTION "similarity_dist"() RETURNS REAL AS $$ similarity_dist $$//
DELIMITER ;

-- Dumping structure for function public.similarity_op
DELIMITER //
CREATE FUNCTION "similarity_op"() RETURNS BOOLEAN AS $$ similarity_op $$//
DELIMITER ;

-- Dumping structure for table public.system_health
CREATE TABLE IF NOT EXISTS "system_health" (
	"component_name" TEXT NOT NULL,
	"component_type" TEXT NOT NULL,
	"status" TEXT NOT NULL,
	"last_check_at" TIMESTAMPTZ NOT NULL DEFAULT now(),
	"version" TEXT NULL DEFAULT NULL,
	"details_json" JSONB NOT NULL DEFAULT '{}',
	"updated_at" TIMESTAMPTZ NOT NULL DEFAULT now(),
	PRIMARY KEY ("component_name")
);

-- Data exporting was unselected.

-- Dumping structure for function public.strict_word_similarity
DELIMITER //
CREATE FUNCTION "strict_word_similarity"() RETURNS REAL AS $$ strict_word_similarity $$//
DELIMITER ;

-- Dumping structure for function public.strict_word_similarity_commutator_op
DELIMITER //
CREATE FUNCTION "strict_word_similarity_commutator_op"() RETURNS BOOLEAN AS $$ strict_word_similarity_commutator_op $$//
DELIMITER ;

-- Dumping structure for function public.strict_word_similarity_dist_commutator_op
DELIMITER //
CREATE FUNCTION "strict_word_similarity_dist_commutator_op"() RETURNS REAL AS $$ strict_word_similarity_dist_commutator_op $$//
DELIMITER ;

-- Dumping structure for function public.strict_word_similarity_dist_op
DELIMITER //
CREATE FUNCTION "strict_word_similarity_dist_op"() RETURNS REAL AS $$ strict_word_similarity_dist_op $$//
DELIMITER ;

-- Dumping structure for function public.strict_word_similarity_op
DELIMITER //
CREATE FUNCTION "strict_word_similarity_op"() RETURNS BOOLEAN AS $$ strict_word_similarity_op $$//
DELIMITER ;

-- Dumping structure for table public.vulnerability_source_state
CREATE TABLE IF NOT EXISTS "vulnerability_source_state" (
	"source_name" TEXT NOT NULL,
	"last_success_at" TIMESTAMPTZ NULL DEFAULT NULL,
	"last_cursor" TEXT NULL DEFAULT NULL,
	"etag" TEXT NULL DEFAULT NULL,
	"details_json" JSONB NOT NULL DEFAULT '{}',
	"updated_at" TIMESTAMPTZ NOT NULL DEFAULT now(),
	PRIMARY KEY ("source_name")
);

-- Data exporting was unselected.

-- Dumping structure for function public.word_similarity
DELIMITER //
CREATE FUNCTION "word_similarity"() RETURNS REAL AS $$ word_similarity $$//
DELIMITER ;

-- Dumping structure for function public.word_similarity_commutator_op
DELIMITER //
CREATE FUNCTION "word_similarity_commutator_op"() RETURNS BOOLEAN AS $$ word_similarity_commutator_op $$//
DELIMITER ;

-- Dumping structure for function public.word_similarity_dist_commutator_op
DELIMITER //
CREATE FUNCTION "word_similarity_dist_commutator_op"() RETURNS REAL AS $$ word_similarity_dist_commutator_op $$//
DELIMITER ;

-- Dumping structure for function public.word_similarity_dist_op
DELIMITER //
CREATE FUNCTION "word_similarity_dist_op"() RETURNS REAL AS $$ word_similarity_dist_op $$//
DELIMITER ;

-- Dumping structure for function public.word_similarity_op
DELIMITER //
CREATE FUNCTION "word_similarity_op"() RETURNS BOOLEAN AS $$ word_similarity_op $$//
DELIMITER ;

/*!40103 SET TIME_ZONE=IFNULL(@OLD_TIME_ZONE, 'system') */;
/*!40101 SET SQL_MODE=IFNULL(@OLD_SQL_MODE, '') */;
/*!40014 SET FOREIGN_KEY_CHECKS=IFNULL(@OLD_FOREIGN_KEY_CHECKS, 1) */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40111 SET SQL_NOTES=IFNULL(@OLD_SQL_NOTES, 1) */;
