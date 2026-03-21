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
 *
 * Threat context:
 *   VT API keys are extremely valuable for threat actors:
 *   - Free keys: 4 lookups/min, 500/day (useful for bulk IOC checking)
 *   - Premium/Enterprise keys: unlimited lookups, retrohunt, livehunt access
 *   - VT Intelligence keys grant access to malware download and YARA retro-hunting
 *   - Leaked premium keys are actively traded on underground forums
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
        // Standard VT API v3 header
        $header1    = /x-apikey[ \t]*:[ \t]*[0-9a-f]{64}/ nocase
        $header2    = /X-Apikey:[ \t]*[0-9a-f]{64}/

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
        // VT_API_KEY
        $env1         = /VT[_.]API[_.]KEY[ \t]*=[ \t]*['"]?[0-9a-f]{64}['"]?/ nocase

        // VIRUSTOTAL_API_KEY — with API infix
        $env2a        = /VIRUSTOTAL[_.]API[_.]KEY[ \t]*=[ \t]*['"]?[0-9a-f]{64}['"]?/ nocase
        // VIRUSTOTAL_KEY — without API infix
        $env2b        = /VIRUSTOTAL[_.]KEY[ \t]*=[ \t]*['"]?[0-9a-f]{64}['"]?/ nocase

        // JSON config — vt_api_key
        $json1a       = /"vt[_\-]api[_\-]key"[ \t]*:[ \t]*"[0-9a-f]{64}"/ nocase
        // JSON config — virustotal_api_key
        $json1b       = /"virustotal[_\-]api[_\-]key"[ \t]*:[ \t]*"[0-9a-f]{64}"/ nocase

        // YAML config — vt_api_key
        $yaml1a       = /vt[_\-]api[_\-]key[ \t]*:[ \t]*['"]?[0-9a-f]{64}['"]?/ nocase
        // YAML config — virustotal_api_key
        $yaml1b       = /virustotal[_\-]api[_\-]key[ \t]*:[ \t]*['"]?[0-9a-f]{64}['"]?/ nocase

        // Python / SDK instantiation
        $sdk_py       = /vt\.Client[ \t]*\([ \t]*['"][0-9a-f]{64}['"][ \t]*\)/
        $sdk_py2      = /api_key[ \t]*=[ \t]*['"][0-9a-f]{64}['"]/

        // VirusTotal endpoint anchor with API key
        $endpoint     = /virustotal\.com[^"'\s]{0,50}[?&]apikey=[0-9a-f]{64}/

    condition:
        any of them
}
