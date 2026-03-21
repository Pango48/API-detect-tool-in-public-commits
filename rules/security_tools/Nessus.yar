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
        // Full X-ApiKeys header with both key pair
        $header_full  = /X-ApiKeys[ \t]*:[ \t]*accessKey=[0-9a-f]{64}[ \t]*;[ \t]*secretKey=[0-9a-f]{64}/ nocase

        // Partial match — just the header name with an accessKey
        $header_part  = /X-ApiKeys[ \t]*:[ \t]*accessKey=[0-9a-f]{64}/ nocase

        // Python requests / integration scripts format
        $py_header    = /'X-ApiKeys'[ \t]*:[ \t]*f?['"]accessKey=[0-9a-f]{64}[ \t]*;[ \t]*secretKey=[0-9a-f]{64}['"]/

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
        // Access key — TENABLE prefix
        $access_env_t  = /TENABLE[_.]ACCESS[_.]KEY[ \t]*=[ \t]*['"]?[0-9a-f]{64}['"]?/ nocase
        // Access key — NESSUS prefix
        $access_env_n  = /NESSUS[_.]ACCESS[_.]KEY[ \t]*=[ \t]*['"]?[0-9a-f]{64}['"]?/ nocase
        // Access key — generic variable
        $access_var    = /access[_.]key[ \t]*=[ \t]*['"][0-9a-f]{64}['"]/ nocase

        // Secret key — TENABLE prefix
        $secret_env_t  = /TENABLE[_.]SECRET[_.]KEY[ \t]*=[ \t]*['"]?[0-9a-f]{64}['"]?/ nocase
        // Secret key — NESSUS prefix
        $secret_env_n  = /NESSUS[_.]SECRET[_.]KEY[ \t]*=[ \t]*['"]?[0-9a-f]{64}['"]?/ nocase
        // Secret key — generic variable
        $secret_var    = /secret[_.]key[ \t]*=[ \t]*['"][0-9a-f]{64}['"]/ nocase

        // JSON config
        $json_acc      = /"access[Kk]ey"[ \t]*:[ \t]*"[0-9a-f]{64}"/
        $json_sec      = /"secret[Kk]ey"[ \t]*:[ \t]*"[0-9a-f]{64}"/

        // Tenable endpoint anchors
        $endpoint      = "cloud.tenable.com"
        $endpoint2     = "localhost:8834"

    condition:
        // High confidence: both keys present
        (($access_env_t or $access_env_n or $access_var or $json_acc)
         and ($secret_env_t or $secret_env_n or $secret_var or $json_sec))
        or
        // Medium confidence: one key + endpoint anchor
        (($access_env_t or $access_env_n or $secret_env_t or $secret_env_n)
         and ($endpoint or $endpoint2))
        or
        // High confidence: explicit Tenable/Nessus-prefixed env vars
        $access_env_t or $access_env_n or $secret_env_t or $secret_env_n
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
        $cookie_hdr  = /X-Cookie[ \t]*:[ \t]*token=[A-Za-z0-9]{32,}/ nocase
        $nessus_ep   = "localhost:8834"
        $token_var   = /token[ \t]*=[ \t]*['"][A-Za-z0-9]{32,}['"]/

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
        $sc_header    = /X-SecurityCenter[ \t]*:[ \t]*[0-9]{1,10}/ nocase
        $sc_apikey    = /x-apikey[ \t]*:[ \t]*[0-9a-f]{64}/ nocase

        // TENABLE_SC_API_KEY — with SC prefix, with API infix
        $sc_env_t_ak  = /TENABLE[_.]SC[_.]API[_.]KEY[ \t]*=[ \t]*['"]?[0-9a-f]{64}['"]?/ nocase
        // TENABLE_SC_KEY — with SC prefix, without API infix
        $sc_env_t_k   = /TENABLE[_.]SC[_.]KEY[ \t]*=[ \t]*['"]?[0-9a-f]{64}['"]?/ nocase
        // SECURITY_CENTER_API_KEY — with SECURITY_CENTER prefix, with API infix
        $sc_env_s_ak  = /SECURITY[_.]CENTER[_.]API[_.]KEY[ \t]*=[ \t]*['"]?[0-9a-f]{64}['"]?/ nocase
        // SECURITY_CENTER_KEY — with SECURITY_CENTER prefix, without API infix
        $sc_env_s_k   = /SECURITY[_.]CENTER[_.]KEY[ \t]*=[ \t]*['"]?[0-9a-f]{64}['"]?/ nocase

    condition:
        any of them
}
