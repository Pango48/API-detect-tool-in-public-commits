/*
 * YARA Rules: VirusTotal API Credentials
 *
 * Author      : BERTON Jules - MORETTI Enzo
 * Date        : 19-03-2026
 * Version     : 1.0
 * Reference   : https://docs.virustotal.com/reference/overview
 *
 * Coverage:
 *   - VirusTotal API v3 keys (64-char hexadecimal)
 *   - VT API key in HTTP headers (x-apikey)
 *   - VT API key in URL query parameters
 *   - VT Enterprise / Intelligence API keys (same format, broader scope)
 *
 * Key format:
 *   VirusTotal API keys are 64-character lowercase hexadecimal strings.
 *   They are passed via the HTTP header "x-apikey" or as a query param "apikey".
 *   Example from official Tenable/CrowdStrike integration docs:
 *     2c935f507d0686382bb383e4daf92eef8b4a349b9b9de2bf85343c0f7e7265db
 *
 * Threat context:
 *   VT API keys are extremely valuable for threat actors:
 *   - Free keys: 4 lookups/min, 500/day (useful for bulk IOC checking)
 *   - Premium/Enterprise keys: unlimited lookups, retrohunt, livehunt access
 *   - VT Intelligence keys grant access to malware download and YARA retro-hunting
 *     (SentinelOne used VT retro-hunt to find 6000+ Anthropic/OpenAI keys)
 *   - Leaked premium keys are actively traded on underground forums
 *
 * False positive guidance:
 *   64-char hex strings appear in many contexts (MD5 pairs, SHA-256 truncated, etc.).
 *   Always require a variable name anchor or header context for high confidence.
 */

rule VirusTotal_API_Key_In_Header
{
    meta:
        description    = "Detects VirusTotal API keys in HTTP headers (x-apikey) or curl commands"
        author         = "BERTON Jules - MORETTI Enzo"
        date           = "19-03-2026"
        version        = "1.0"
        reference      = "https://docs.virustotal.com/reference/overview"
        confidence     = "HIGH"
        false_positive = "LOW"
        severity       = "HIGH"
        tags           = "virustotal,api-key,http-header,threat-intel"

    strings:
        // Standard VT API v3 header — documented in official VT curl examples
        $header1    = /x-apikey\s*:\s*[0-9a-f]{64}/  nocase
        $header2    = /X-Apikey:\s*[0-9a-f]{64}/

        // URL query parameter form (v2 legacy and some integrations)
        $url_param  = /[?&]apikey=[0-9a-f]{64}/

    condition:
        any of them
}


rule VirusTotal_API_Key_In_Config
{
    meta:
        description    = "Detects VirusTotal API keys in config files, env files, and source code"
        author         = "BERTON Jules - MORETTI Enzo"
        date           = "19-03-2026"
        version        = "1.0"
        reference      = "https://docs.virustotal.com/reference/overview"
        confidence     = "HIGH"
        false_positive = "LOW"
        severity       = "HIGH"
        tags           = "virustotal,api-key,config,env"

    strings:
        // Environment variable patterns
        $env1       = /VT[_\.]?API[_\.]?KEY\s*=\s*['"]?[0-9a-f]{64}['"]?/  nocase
        $env2       = /VIRUSTOTAL[_\.]?(?:API[_\.]?)?KEY\s*=\s*['"]?[0-9a-f]{64}['"]?/  nocase

        // JSON/YAML config patterns
        $json1      = /"(?:vt|virustotal)[_\-]?api[_\-]?key"\s*:\s*"[0-9a-f]{64}"/  nocase
        $yaml1      = /(?:vt|virustotal)[_\-]?api[_\-]?key\s*:\s*['"]?[0-9a-f]{64}['"]?/  nocase

        // Python / SDK instantiation
        $sdk_py     = /vt\.Client\s*\(\s*['"][0-9a-f]{64}['"]\s*\)/
        $sdk_py2    = /api_key\s*=\s*['"][0-9a-f]{64}['"]/

        // VirusTotal endpoint anchor with API key
        $endpoint   = /virustotal\.com[^"'\s]{0,50}[?&]apikey=[0-9a-f]{64}/

    condition:
        any of them
}
