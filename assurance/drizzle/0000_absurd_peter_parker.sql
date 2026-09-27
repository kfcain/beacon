CREATE TABLE `beacon_workspaces` (
	`owner` text PRIMARY KEY NOT NULL,
	`revision` integer DEFAULT 0 NOT NULL,
	`body` text NOT NULL,
	`updated_at` text NOT NULL
);
