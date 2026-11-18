-- Seven more facts of a file's type (PLAN.md decision 25, docs/decisions/0003): the first-byte tests
-- of the modules that decide by them, made once by the type step so the modules declare on them
-- (ace_results' TypeFacts). Each is the module's own test, not libmagic's answer.
--
-- NULL in a row the type step wrote before these columns: the core reads such a row as no type at
-- all (ace_core::type_step::facts_of), so a declaration's condition on it holds and the file is typed
-- again where it is next needed, which fills them. A type step always writes all seven.
ALTER TABLE store.file_types
    ADD COLUMN is_pcap_file boolean,
    ADD COLUMN has_onenote_header boolean,
    ADD COLUMN is_java_class_file boolean,
    ADD COLUMN has_xml_marker boolean,
    ADD COLUMN is_eps_file boolean,
    ADD COLUMN is_encoded_script boolean,
    ADD COLUMN has_har_header boolean;
