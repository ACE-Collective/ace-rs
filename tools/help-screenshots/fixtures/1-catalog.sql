-- tools/help-screenshots: what the launcher's calls need before they are made. Every name, host,
-- address, hash and id here is made up for the screenshots; nothing is from a real ACE, a signatures
-- repository or Atomic Red Team. The tests are the guides' own examples.
--
-- psql variables: yara_x (the yara-x version the binary scans with, which names the current ruleset).

\set ON_ERROR_STOP on
BEGIN;

-- The lab: five test hosts.
INSERT INTO svs.test_hosts (hostname, fqdn, usernames, ips, platform, notes, created_by)
SELECT host, host || '.lab.example.com', users, ips, platform, notes,
       jsonb_build_object('kind', 'user', 'id', u.id, 'name', u.username)
FROM service.users u,
     (VALUES ('win10-art-01', '{art}'::text[], '{10.20.30.11}'::text[], 'windows', 'Windows 10 22H2, the nightly batch'),
             ('win10-art-02', '{art}', '{10.20.30.12}', 'windows', 'Windows 10 22H2, the nightly batch'),
             ('win10-art-03', '{art,svc-web}', '{10.20.30.13}', 'windows', 'Domain joined, for the Kerberos tests'),
             ('ubuntu-art-01', '{art}', '{10.20.30.21}', 'linux', 'Ubuntu 24.04'),
             ('mac-art-01', '{art}', '{10.20.30.31}', 'macos', NULL))
         AS h (host, users, ips, platform, notes)
WHERE u.username = 'alice';

-- The catalog: one repository and ten tests, written for this fixture.
INSERT INTO svs.catalog_repositories (name, commit, refreshed_at, test_count)
VALUES ('atomic-red-team', 'c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00', now() - interval '3 minutes', 10);

INSERT INTO svs.catalog_tests
    (guid, repository, technique, technique_name, name, description, platforms, executor, test,
     content_hash, commit, path, first_seen_at)
SELECT guid::uuid, 'atomic-red-team', technique, technique_name, name, description, platforms, executor,
       jsonb_build_object(
           'name', name, 'auto_generated_guid', guid, 'description', description,
           'supported_platforms', to_jsonb(platforms),
           'input_arguments', jsonb_build_object(
               'marker', jsonb_build_object('description', 'The run''s marker, which the launcher passes',
                                            'type', 'string', 'default', 'art_marker')),
           'executor', jsonb_build_object('name', executor, 'command', command,
                                          'cleanup_command', cleanup, 'elevation_required', elevated)),
       encode(sha256(convert_to(guid || command, 'UTF8')), 'hex'),
       'c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00', 'atomics/' || technique || '/' || technique || '.yaml',
       now() - interval '40 days'
FROM (VALUES
    ('7e570001-0000-4000-8000-000000000001', 'T1558.003', 'Steal or Forge Kerberos Tickets: Kerberoasting',
     'Request for service tickets',
     'Asks the domain controller for a service ticket of each account with a service principal name, as a Kerberoasting tool does.',
     '{windows}'::text[], 'powershell',
     'Invoke-FixtureKerberoast -Domain lab.example.com -Marker #{marker}', 'Remove-Item $env:TEMP\tickets-#{marker}.txt', false),
    ('7e570001-0000-4000-8000-000000000002', 'T1003.002', 'OS Credential Dumping: Security Account Manager',
     'Save the SAM hive with reg save',
     'Saves the SAM registry hive to a file, which holds the local accounts'' password hashes.',
     '{windows}', 'command_prompt',
     'reg save HKLM\SAM %TEMP%\sam-#{marker}.save', 'del %TEMP%\sam-#{marker}.save', true),
    ('7e570001-0000-4000-8000-000000000003', 'T1059.001', 'Command and Scripting Interpreter: PowerShell',
     'Run an encoded PowerShell command',
     'Starts PowerShell with a base64 command that writes the marker to a file.',
     '{windows}', 'powershell',
     'powershell.exe -EncodedCommand (ConvertTo-FixtureBase64 "Set-Content marker.txt #{marker}")', 'Remove-Item marker.txt', false),
    ('7e570001-0000-4000-8000-000000000004', 'T1136.001', 'Create Account: Local Account',
     'Create a local account with net user',
     'Creates a local account named after the marker.',
     '{windows}', 'command_prompt',
     'net user art-#{marker} Fixture-Passw0rd! /add', 'net user art-#{marker} /delete', true),
    ('7e570001-0000-4000-8000-000000000005', 'T1053.005', 'Scheduled Task/Job: Scheduled Task',
     'Create a scheduled task that runs at logon',
     'Registers a task that starts a script when a user logs on. The task stays until the cleanup.',
     '{windows}', 'command_prompt',
     'schtasks /create /tn art-#{marker} /tr %TEMP%\art.cmd /sc onlogon', 'schtasks /delete /tn art-#{marker} /f', true),
    ('7e570001-0000-4000-8000-000000000006', 'T1105', 'Ingress Tool Transfer',
     'Download a file with certutil',
     'Downloads a text file from the lab''s web server with certutil.',
     '{windows}', 'command_prompt',
     'certutil -urlcache -split -f http://files.lab.example.com/#{marker}.txt %TEMP%\#{marker}.txt', 'del %TEMP%\#{marker}.txt', false),
    ('7e570001-0000-4000-8000-000000000007', 'T1548.001', 'Abuse Elevation Control Mechanism: Setuid and Setgid',
     'Set the setuid bit on a copied shell',
     'Copies a shell and sets its setuid bit.',
     '{linux}', 'sh',
     'cp /bin/sh /tmp/sh-#{marker} && chmod u+s /tmp/sh-#{marker}', 'rm -f /tmp/sh-#{marker}', true),
    ('7e570001-0000-4000-8000-000000000008', 'T1543.001', 'Create or Modify System Process: Launch Agent',
     'Install a launch agent',
     'Writes a launch agent property list that starts a script at login.',
     '{macos}', 'sh',
     'cp fixture.plist ~/Library/LaunchAgents/com.example.#{marker}.plist', 'rm ~/Library/LaunchAgents/com.example.#{marker}.plist', false),
    ('7e570001-0000-4000-8000-000000000009', 'T1003.001', 'OS Credential Dumping: LSASS Memory',
     'Dump LSASS memory with comsvcs',
     'Writes a memory dump of the LSASS process with the comsvcs library.',
     '{windows}', 'powershell',
     'rundll32.exe comsvcs.dll, MiniDump (Get-Process lsass).Id $env:TEMP\lsass-#{marker}.dmp full', 'Remove-Item $env:TEMP\lsass-#{marker}.dmp', true),
    ('7e570001-0000-4000-8000-00000000000a', 'T1053.003', 'Scheduled Task/Job: Cron',
     'Add a cron job',
     'Adds a line to the test user''s crontab.',
     '{linux,macos}', 'sh',
     '(crontab -l; echo "* * * * * /tmp/#{marker}.sh") | crontab -', 'crontab -r', false)
) AS t (guid, technique, technique_name, name, description, platforms, executor, command, cleanup, elevated);

-- The scheduled task test leaves its task behind, and its signatures fire within minutes.
INSERT INTO svs.test_settings (test_guid, observation_minutes, holds_host, set_by)
SELECT '7e570001-0000-4000-8000-000000000005', 90, true,
       jsonb_build_object('kind', 'user', 'id', id, 'name', username)
FROM service.users WHERE username = 'alice';

-- The hunts the hunter recorded, each with what SVS reads of it.
INSERT INTO hunts.hunts (type, path, name, uuid, enabled, frequency, loaded_at, svs)
SELECT 'splunk', 'hunts/splunk/' || lower(name) || '.yaml', name, uuid, true, '00:10:00', now() - interval '2 hours',
       jsonb_build_object('uuid', uuid, 'name', name, 'enabled', true, 'latency_seconds', latency,
                          'suppression_seconds', NULL, 'per_group', false,
                          'content_hash', encode(sha256(convert_to(name, 'UTF8')), 'hex'), 'tags', to_jsonb(tags))
FROM (VALUES
    ('5160a000-0000-4000-8000-000000000001', 'CA_PowerShell_Invoke_Kerberoast', 1200, '{mitre:T1558.003}'::text[]),
    ('5160a000-0000-4000-8000-000000000002', 'EX_PowerShell_Download_Cradle', 900, '{mitre:T1105,mitre:T1059.001}'),
    ('5160a000-0000-4000-8000-000000000006', 'CA_Schtasks_Logon_Task', 900, '{mitre:T1053.005,mitre:T1547.001}'),
    ('5160a000-0000-4000-8000-000000000007', 'EX_Certutil_Download', 900, '{mitre:T1105}'),
    -- tagged with a technique no test measures, and not with the one its test does
    ('5160a000-0000-4000-8000-000000000008', 'LX_Chmod_Setuid_Shell', 1800, '{mitre:T1222.002}'),
    ('5160a000-0000-4000-8000-000000000009', 'EX_WinRM_Remote_Shell', 900, '{mitre:T1021.006}')
) AS h (uuid, name, latency, tags);

-- The ruleset the pools scan with: three rules that alert and two in QA mode.
INSERT INTO yara.rulesets (key, commit, tree, sources_sha256, yara_x_version, files, left_out, qa_rules, signatures)
VALUES (
    repeat('5e', 32), 'feedface00feedface00feedface00feedface00', repeat('7e', 20), repeat('5a', 32), :'yara_x',
    '[]', '[]',
    jsonb_build_array(
        jsonb_build_object(
            'namespace', 'detection_rules', 'path', 'qa/QA_Office_Macro_Shell.yar', 'name', 'QA_Office_Macro_Shell',
            'uuid', '5160a000-0000-4000-8000-00000000000b', 'enabled', true, 'tags', jsonb_build_array('qa')),
        -- one that hasn't matched anything yet
        jsonb_build_object(
            'namespace', 'detection_rules', 'path', 'qa/QA_Lnk_Startup_Folder.yar', 'name', 'QA_Lnk_Startup_Folder',
            'uuid', '5160a000-0000-4000-8000-00000000000d', 'enabled', true, 'tags', jsonb_build_array('qa'))),
    (SELECT jsonb_agg(jsonb_build_object(
                'uuid', uuid, 'name', name, 'content_hash', encode(sha256(convert_to(name, 'UTF8')), 'hex'),
                'tags', to_jsonb(tags), 'counts', true))
     FROM (VALUES
         ('5160a000-0000-4000-8000-000000000003', 'EX_PowerShell_Encoded_Command', '{mitre:T1027,mitre:T1059.001}'::text[]),
         ('5160a000-0000-4000-8000-000000000004', 'CA_Registry_SAM_Save', '{mitre:T1003.002,mitre:T1012}'),
         ('7a1d0000-5e5f-4c11-9000-000000000005', 'PE_Net_User_Add', '{mitre:T1098,mitre:T1136.001}')
     ) AS s (uuid, name, tags)));

COMMIT;
