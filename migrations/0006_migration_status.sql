-- Track migration status for each federation version.
--
-- The current (latest) version is always 'not_applicable'.
-- Older versions start as 'pending' once a newer federation is created,
-- move to 'in_progress' during sweep execution, and end at 'complete'.

ALTER TABLE federation_versions
    ADD COLUMN migration_status TEXT NOT NULL DEFAULT 'not_applicable'
        CHECK (migration_status IN (
            'not_applicable',
            'pending',
            'in_progress',
            'complete'
        ));
