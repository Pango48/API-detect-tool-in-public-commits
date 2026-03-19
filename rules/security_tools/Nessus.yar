/*
 * YARA Rules: Tenable Nessus / Tenable.io / Tenable.sc API Credentials
 *
 * Author      : BERTON Jules - MORETTI Enzo
 * Date        : 19-03-2026
 * Version     : 1.0
 * Reference   : https://developer.tenable.com/docs/authorization
 *               https://docs.tenable.com/nessus/Content/SettingsMyAccount.htm
 *
 * Coverage:
 *   - Tenable.io / Tenable Vulnerability Management API key pair
 *     (accessKey + secretKey, each 64 hex chars)
 *   - X-ApiKeys HTTP header (canonical Tenable auth header)
 *   - Nessus session token (X-Cookie: token=...)
 *   - Tenable.sc (SecurityCenter) API key
 *
 * Key format (from official Tenable developer docs):
 *   Both accessKey and secretKey are 64-character lowercase hexadecimal strings.
 *   They are ALWAYS passed together in a single header:
 *     X-ApiKeys: accessKey=<64hex>; secretKey=<64hex>
 *
 *   Example from official Tenable documentation:
 *     X-ApiKeys: accessKey=2c935f507d0686382bb383e4daf92eef8b4a349b9b9de2bf85343c0f7e7265db;
 *                secretKey=0553ac5757e8e741d6ef034dc06618106e7855887428e662adcde8862d017cf9
 *
 *   Nessus (self-hosted) additionally supports session token auth via:
 *     X-Cookie: token=<session_token>
 *
 * Threat context:
 *   A leaked Tenable API key pair grants full control over vulnerability scan data:
 *   - Access to all scan results and vulnerability findings for the organization
 *   - Ability to create/modify/delete scans and scan policies
 *   - Access to asset inventory and credential data
 *   - On Tenable.io: access to cloud connector credentials stored in the platform
 */

rule Tenable_API_Keys_Header
{
    meta:
        description    = "Detects Tenable Nessus/Tenable.io X-ApiKeys header with accessKey+secretKey pair"
        author         = "BERTON Jules - MORETTI Enzo"
        date           = "19-03-2026"
        version        = "1.0"
        reference      = "https://developer.tenable.com/docs/authorization"
        confidence     = "HIGH"
        false_positive = "LOW"
        severity       = "CRITICAL"
        tags           = "tenable,nessus,api-key,x-apikeys,header"

    strings:
        // Full X-ApiKeys header with both key pair — from official Tenable curl examples
        $header_full  = /X-ApiKeys\s*:\s*accessKey=[0-9a-f]{64}\s*;\s*secretKey=[0-9a-f]{64}/  nocase

        // Partial match — just the header name with an accessKey
        $header_part  = /X-ApiKeys\s*:\s*accessKey=[0-9a-f]{64}/  nocase

        // Python requests / integration scripts format
        $py_header    = /'X-ApiKeys'\s*:\s*f?['"]accessKey=[0-9a-f]{64}\s*;\s*secretKey=[0-9a-f]{64}['"]/

    condition:
        any of them
}


rule Tenable_API_Keys_In_Config
{
    meta:
        description    = "Detects Tenable accessKey and secretKey in config files, env files, or source code"
        author         = "BERTON Jules - MORETTI Enzo"
        date           = "19-03-2026"
        version        = "1.0"
        reference      = "https://developer.tenable.com/docs/authorization"
        confidence     = "HIGH"
        false_positive = "LOW"
        severity       = "CRITICAL"
        tags           = "tenable,nessus,api-key,config,env"

    strings:
        // Access key variable patterns
        $access_env   = /(?:TENABLE|NESSUS)[_\.]?ACCESS[_\.]?KEY\s*=\s*['"]?[0-9a-f]{64}['"]?/  nocase
        $access_var   = /access[_\.]?key\s*=\s*['"][0-9a-f]{64}['"]/  nocase

        // Secret key variable patterns
        $secret_env   = /(?:TENABLE|NESSUS)[_\.]?SECRET[_\.]?KEY\s*=\s*['"]?[0-9a-f]{64}['"]?/  nocase
        $secret_var   = /secret[_\.]?key\s*=\s*['"][0-9a-f]{64}['"]/  nocase

        // JSON config
        $json_acc     = /"access[Kk]ey"\s*:\s*"[0-9a-f]{64}"/
        $json_sec     = /"secret[Kk]ey"\s*:\s*"[0-9a-f]{64}"/

        // Tenable endpoint anchor (confirms Tenable context for generic variable names)
        $endpoint     = "cloud.tenable.com"
        $endpoint2    = "localhost:8834"

    condition:
        // High confidence: both keys present
        (($access_env or $access_var or $json_acc) and ($secret_env or $secret_var or $json_sec))
        or
        // Medium confidence: one key + endpoint anchor
        (($access_env or $secret_env) and ($endpoint or $endpoint2))
        or
        // High confidence: explicit Tenable-prefixed env vars
        $access_env or $secret_env
}


rule Nessus_Session_Token
{
    meta:
        description    = "Detects Nessus self-hosted session tokens in X-Cookie headers or config"
        author         = "BERTON Jules - MORETTI Enzo"
        date           = "19-03-2026"
        version        = "1.0"
        reference      = "https://developer.tenable.com/reference/session-create"
        confidence     = "MEDIUM"
        false_positive = "MEDIUM"
        severity       = "HIGH"
        tags           = "tenable,nessus,session-token,x-cookie"

    strings:
        // Nessus session token header
        $cookie_hdr   = /X-Cookie\s*:\s*token=[A-Za-z0-9]{32,}/  nocase

        // Session token in scripts with Nessus endpoint
        $nessus_ep    = "localhost:8834"
        $token_var    = /token\s*=\s*['"][A-Za-z0-9]{32,}['"]/

    condition:
        $cookie_hdr or ($nessus_ep and $token_var)
}


rule Tenable_SC_API_Key
{
    meta:
        description    = "Detects Tenable.sc (SecurityCenter) API key in config or HTTP headers"
        author         = "BERTON Jules - MORETTI Enzo"
        date           = "19-03-2026"
        version        = "1.0"
        reference      = "https://docs.tenable.com/security-center/Content/RESTAPI.htm"
        confidence     = "MEDIUM"
        false_positive = "MEDIUM"
        severity       = "HIGH"
        tags           = "tenable,securitycenter,sc,api-key"

    strings:
        // Tenable.sc uses X-SecurityCenter header with numeric session ID
        // and x-apikey for key-based auth
        $sc_header  = /X-SecurityCenter\s*:\s*[0-9]{1,10}/  nocase
        $sc_apikey  = /x-apikey\s*:\s*[0-9a-f]{64}/  nocase

        // Environment variable
        $sc_env     = /(?:TENABLE[_\.]?SC|SECURITY[_\.]?CENTER)[_\.]?(?:API[_\.]?)?KEY\s*=\s*['"]?[0-9a-f]{64}['"]?/  nocase

    condition:
        any of them
}
