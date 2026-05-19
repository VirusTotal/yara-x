// This content is shown by default when the playground first opens in the browser
export const DEFAULT_SAMPLE_RULE = `rule suspicious_download_example {
    meta:
        author      = "YARA-X Playground"
        description = "Example rule used in the playground"
    strings:
        $a = "powershell" nocase
        $b = "download" nocase
        $c = "http://" nocase
    condition:
        2 of them
}`;

export const DEFAULT_SAMPLE_INPUT = `powershell -command download http://example.com/payload`;
