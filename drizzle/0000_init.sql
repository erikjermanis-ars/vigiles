CREATE TABLE `advisories` (
	`osv_id` text PRIMARY KEY NOT NULL,
	`aliases` text DEFAULT '[]' NOT NULL,
	`cves` text DEFAULT '[]' NOT NULL,
	`summary` text,
	`details` text,
	`cvss_vector` text,
	`cvss_score` real,
	`severity_label` text,
	`cwes` text DEFAULT '[]' NOT NULL,
	`references` text DEFAULT '[]' NOT NULL,
	`published` text,
	`modified` text,
	`withdrawn` text,
	`malicious` integer DEFAULT false NOT NULL,
	`raw` text NOT NULL,
	`updated_at` text DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')) NOT NULL
);
--> statement-breakpoint
CREATE TABLE `decisions` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`finding_id` integer NOT NULL,
	`policy_hash` text NOT NULL,
	`config_name` text NOT NULL,
	`triage_run_id` integer,
	`action` text NOT NULL,
	`rule_id` text NOT NULL,
	`inputs` text NOT NULL,
	`decided_at` text DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')) NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `decisions_key_idx` ON `decisions` (`finding_id`,`policy_hash`,`config_name`);--> statement-breakpoint
CREATE TABLE `events` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`finding_id` integer NOT NULL,
	`type` text NOT NULL,
	`job_run_id` integer,
	`data` text,
	`at` text DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')) NOT NULL
);
--> statement-breakpoint
CREATE INDEX `events_finding_idx` ON `events` (`finding_id`);--> statement-breakpoint
CREATE INDEX `events_at_idx` ON `events` (`at`);--> statement-breakpoint
CREATE TABLE `feed_state` (
	`feed` text PRIMARY KEY NOT NULL,
	`last_success_at` text,
	`last_attempt_at` text,
	`last_error` text,
	`meta` text
);
--> statement-breakpoint
CREATE TABLE `findings` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`project_id` text NOT NULL,
	`lockfile` text NOT NULL,
	`ecosystem` text NOT NULL,
	`package_name` text NOT NULL,
	`osv_id` text NOT NULL,
	`installed_versions` text DEFAULT '[]' NOT NULL,
	`fixed_versions` text DEFAULT '[]' NOT NULL,
	`direct` integer,
	`dev_only` integer DEFAULT false NOT NULL,
	`paths` text DEFAULT '[]' NOT NULL,
	`import_sites` text DEFAULT '[]' NOT NULL,
	`status` text DEFAULT 'open' NOT NULL,
	`origin` text NOT NULL,
	`first_seen_scan_id` integer NOT NULL,
	`last_seen_scan_id` integer NOT NULL,
	`first_seen_at` text DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')) NOT NULL,
	`resolved_at` text,
	`advisory_modified` text,
	`priority` text,
	`priority_reasons` text DEFAULT '[]' NOT NULL,
	`in_kev` integer DEFAULT false NOT NULL,
	`kev_date_added` text,
	`epss` real,
	`epss_percentile` real,
	`cvss_score` real,
	`enriched_at` text,
	`current_action` text,
	`current_rule_id` text,
	`active_triage_run_id` integer,
	`decided_at` text,
	`created_at` text DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')) NOT NULL,
	`updated_at` text DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')) NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `findings_key_idx` ON `findings` (`project_id`,`lockfile`,`ecosystem`,`package_name`,`osv_id`);--> statement-breakpoint
CREATE INDEX `findings_status_idx` ON `findings` (`status`);--> statement-breakpoint
CREATE INDEX `findings_project_idx` ON `findings` (`project_id`);--> statement-breakpoint
CREATE TABLE `inventory` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`scan_id` integer NOT NULL,
	`lockfile` text NOT NULL,
	`ecosystem` text NOT NULL,
	`name` text NOT NULL,
	`version` text NOT NULL,
	`direct` integer,
	`dev_only` integer DEFAULT false NOT NULL
);
--> statement-breakpoint
CREATE INDEX `inventory_scan_idx` ON `inventory` (`scan_id`);--> statement-breakpoint
CREATE INDEX `inventory_name_idx` ON `inventory` (`scan_id`,`lockfile`,`name`);--> statement-breakpoint
CREATE TABLE `job_runs` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`type` text NOT NULL,
	`params` text DEFAULT '{}' NOT NULL,
	`status` text DEFAULT 'queued' NOT NULL,
	`parent_id` integer,
	`progress` text,
	`log` text DEFAULT '' NOT NULL,
	`stats` text,
	`error` text,
	`cancel_requested` integer DEFAULT false NOT NULL,
	`created_at` text DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')) NOT NULL,
	`started_at` text,
	`finished_at` text
);
--> statement-breakpoint
CREATE INDEX `job_runs_status_idx` ON `job_runs` (`status`);--> statement-breakpoint
CREATE INDEX `job_runs_parent_idx` ON `job_runs` (`parent_id`);--> statement-breakpoint
CREATE TABLE `kev` (
	`cve` text PRIMARY KEY NOT NULL,
	`date_added` text,
	`due_date` text,
	`ransomware` text,
	`vendor` text,
	`product` text,
	`name` text,
	`short_description` text
);
--> statement-breakpoint
CREATE TABLE `labels` (
	`finding_id` integer NOT NULL,
	`labeler` text DEFAULT 'me' NOT NULL,
	`expected_action` text NOT NULL,
	`affected_truth` text,
	`note` text,
	`labeled_at` text DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')) NOT NULL,
	PRIMARY KEY(`finding_id`, `labeler`)
);
--> statement-breakpoint
CREATE TABLE `policy_versions` (
	`hash` text PRIMARY KEY NOT NULL,
	`content` text NOT NULL,
	`first_seen_at` text DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')) NOT NULL
);
--> statement-breakpoint
CREATE TABLE `projects` (
	`id` text PRIMARY KEY NOT NULL,
	`name` text NOT NULL,
	`enabled` integer DEFAULT true NOT NULL,
	`repo_path` text NOT NULL,
	`ref` text NOT NULL,
	`profile` text NOT NULL,
	`profile_hash` text NOT NULL,
	`last_scan_id` integer,
	`updated_at` text DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')) NOT NULL
);
--> statement-breakpoint
CREATE TABLE `scans` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`project_id` text NOT NULL,
	`job_run_id` integer,
	`ref` text NOT NULL,
	`commit_sha` text,
	`commit_date` text,
	`fetched` integer DEFAULT false NOT NULL,
	`fetch_error` text,
	`lockfiles` text DEFAULT '[]' NOT NULL,
	`coverage_gaps` text DEFAULT '[]' NOT NULL,
	`osv_db_date` text,
	`status` text DEFAULT 'running' NOT NULL,
	`stats` text,
	`error` text,
	`started_at` text DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')) NOT NULL,
	`finished_at` text
);
--> statement-breakpoint
CREATE INDEX `scans_project_idx` ON `scans` (`project_id`);--> statement-breakpoint
CREATE TABLE `triage_configs` (
	`name` text PRIMARY KEY NOT NULL,
	`prompt_version` text NOT NULL,
	`model` text NOT NULL,
	`effort` text NOT NULL,
	`code_access` integer NOT NULL,
	`active` integer DEFAULT false NOT NULL,
	`created_at` text DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')) NOT NULL
);
--> statement-breakpoint
CREATE TABLE `triage_runs` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`finding_id` integer NOT NULL,
	`config_name` text NOT NULL,
	`job_run_id` integer,
	`input_hash` text NOT NULL,
	`status` text NOT NULL,
	`output` text,
	`raw` text,
	`prompt` text NOT NULL,
	`model_resolved` text,
	`claude_version` text,
	`cost_usd` real,
	`input_tokens` integer,
	`output_tokens` integer,
	`cache_read_tokens` integer,
	`num_turns` integer,
	`duration_ms` integer,
	`attempts` integer DEFAULT 1 NOT NULL,
	`error` text,
	`tag` text,
	`created_at` text DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')) NOT NULL
);
--> statement-breakpoint
CREATE INDEX `triage_runs_finding_idx` ON `triage_runs` (`finding_id`,`config_name`);--> statement-breakpoint
CREATE INDEX `triage_runs_hash_idx` ON `triage_runs` (`finding_id`,`config_name`,`input_hash`);