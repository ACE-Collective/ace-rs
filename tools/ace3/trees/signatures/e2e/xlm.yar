// A name in ace3's and the port's yara_rule_names for the xlmdeobfuscator module, so a file the module's
// own rules don't know is analyzed because of what's below it (samples/ace4/office/xlm_yara_rule.zip).
rule XLM_Macrosheet_NonBin
{
    meta:
        uuid = "b1c7a5f2-6d0e-4b8e-8a4d-2f3e1c9d7b60"
    strings:
        $marker = "ACE4-XLM-RULE-MARKER-9d2e"
    condition:
        $marker
}
