ALTER TABLE `findings` ADD `import_site_count` integer DEFAULT 0 NOT NULL;--> statement-breakpoint
ALTER TABLE `findings` ADD `instances` text DEFAULT '[]' NOT NULL;--> statement-breakpoint
ALTER TABLE `job_runs` ADD `pid` integer;--> statement-breakpoint
ALTER TABLE `projects` ADD `triage_profile_hash` text DEFAULT '' NOT NULL;--> statement-breakpoint
ALTER TABLE `triage_runs` ADD `scan_id` integer;--> statement-breakpoint
ALTER TABLE `triage_runs` ADD `commit_sha` text;