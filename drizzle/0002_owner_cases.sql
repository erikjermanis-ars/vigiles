CREATE TABLE `owner_cases` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`finding_id` integer NOT NULL,
	`status` text DEFAULT 'open' NOT NULL,
	`brief` text NOT NULL,
	`reason` text NOT NULL,
	`system_action` text,
	`agent_action` text,
	`batch` text,
	`answer` text,
	`answered_by` text,
	`note` text,
	`created_at` text DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')) NOT NULL,
	`answered_at` text
);
--> statement-breakpoint
CREATE INDEX `owner_cases_status_idx` ON `owner_cases` (`status`);--> statement-breakpoint
CREATE INDEX `owner_cases_finding_idx` ON `owner_cases` (`finding_id`);