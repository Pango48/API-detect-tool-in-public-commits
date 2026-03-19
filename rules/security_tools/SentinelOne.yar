/*
 * YARA Rules: SentinelOne API Credentials
 *
 * Author      : yara-apikey-rules contributors
 * Date        : 19-03-2026
 * Version     : 1.0
 * License     : MIT
 * Reference   : https://usea1-partners.sentinelone.net/api-doc/
 *               https://www.ninjaone.com/docs/integrations/antivirus/sentinelone/
 *
 * Coverage:
 *   - SentinelOne Management API tokens (opaque Bearer tokens ~150-200 chars)
 *   - SentinelOne API token + management URL pairs
 *   - SentinelOne Singularity Data Lake (XDR) Visibility Enhanced Key
 *   - Service User token in config/env files
 *
 * Token format:
 *   SentinelOne API tokens are opaque strings generated in the Management Console.
 *   They do NOT have a fixed prefix but are always used in combination with a
 *   tenant-specific URL (e.g. usea1-partners.sentinelone.net).
 *   Token length: typically 150-200 Base64-like chars.
 *   One token per user. Expiration: 30 days (renewable).
 *
 *   The most reliable detection anchors are:
 *     1. The *.sentinelone.net domain in proximity to a long token
 *     2. Variable names like SENTINELONE_API_TOKEN, S1_API_TOKEN
 *     3. The Authorization: ApiToken <token> header (SentinelOne-specific header)
 *
 * Threat context:
 *   A leaked SentinelOne API token grants an attacker full EDR control:
 *   - Disable agent protection on any endpoint
 *   - Exclude processes from scanning (enabling malware execution)
 *   - Retrieve threat intelligence and detection data
 *   - Manage groups, sites, and accounts
 */

rule SentinelOne_API_Token_In_Header
{
    meta:
        description    = "Detects SentinelOne API tokens in Authorization headers (ApiToken scheme)"
        author         = "yara-apikey-rules"
        date           = "19-03-2026"
        version        = "1.0"
        reference      = "https://usea1-partners.sentinelone.net/api-doc/"
        confidence     = "HIGH"
        false_positive = "LOW"
        severity       = "CRITICAL"
        tags           = "sentinelone,edr,api-token,authorization-header"

    strings:
        // SentinelOne uses "ApiToken" scheme — not "Bearer" — this is highly distinctive
        $apitoken_hdr = /Authorization:\s*ApiToken\s+[A-Za-z0-9+\/=]{50,}/  nocase

        // Also seen in curl -H form
        $curl_hdr     = /-H\s+['"]Authorization:\s*ApiToken\s+[A-Za-z0-9+\/=]{50,}['"]/  nocase

    condition:
        any of them
}


rule SentinelOne_API_Token_In_Config
{
    meta:
        description    = "Detects SentinelOne API tokens in config files, env files, or source code"
        author         = "yara-apikey-rules"
        date           = "19-03-2026"
        version        = "1.0"
        reference      = "https://www.ninjaone.com/docs/integrations/antivirus/sentinelone/"
        confidence     = "HIGH"
        false_positive = "LOW"
        severity       = "CRITICAL"
        tags           = "sentinelone,edr,api-token,config,env"

    strings:
        // Environment variable anchors
        $env1       = /S1[_\.]?API[_\.]?TOKEN\s*=\s*['"]?[A-Za-z0-9+\/=]{50,}['"]?/  nocase
        $env2       = /SENTINELONE[_\.]?(?:API[_\.]?)?TOKEN\s*=\s*['"]?[A-Za-z0-9+\/=]{50,}['"]?/  nocase
        $env3       = /SENTINELONE[_\.]?API[_\.]?KEY\s*=\s*['"]?[A-Za-z0-9+\/=]{50,}['"]?/  nocase

        // JSON/YAML config with management URL context
        $json1      = /"(?:api[_\-]?token|apiToken)"\s*:\s*"[A-Za-z0-9+\/=]{50,}"/

        // Python SDK / automation scripts
        $sdk_py     = /SentinelOneSDK\s*\(.*token\s*=\s*['"][A-Za-z0-9+\/=]{50,}['"]/  nocase

    condition:
        any of them
}


rule SentinelOne_Credentials_Pair
{
    meta:
        description    = "Detects SentinelOne management URL + API token pair — high confidence credential leak"
        author         = "yara-apikey-rules"
        date           = "19-03-2026"
        version        = "1.0"
        reference      = "https://docs.alertlogic.com/configure/connections/sentinelone.htm"
        confidence     = "HIGH"
        false_positive = "LOW"
        severity       = "CRITICAL"
        tags           = "sentinelone,edr,api-token,management-url,credential-pair"

    strings:
        // SentinelOne management console URL pattern
        $mgmt_url   = /https?:\/\/[a-zA-Z0-9\-]+\.sentinelone\.net/

        // Token variable nearby (more relaxed — catches any substantial token)
        $token_var  = /(?:api[_\-]?token|apiToken|token|api[_\-]?key)\s*[=:"']{1,3}\s*['"]?[A-Za-z0-9+\/=]{50,}['"]?/  nocase

    condition:
        $mgmt_url and $token_var
}


rule SentinelOne_XDR_Visibility_Key
{
    meta:
        description    = "Detects SentinelOne Singularity Data Lake / XDR Visibility Enhanced Key credentials"
        author         = "yara-apikey-rules"
        date           = "19-03-2026"
        version        = "1.0"
        reference      = "https://docs.synqly.com/guides/provider-configuration/sentinelone-setup"
        confidence     = "HIGH"
        false_positive = "LOW"
        severity       = "CRITICAL"
        tags           = "sentinelone,xdr,singularity,data-lake,visibility-key"

    strings:
        // XDR endpoint anchor
        $xdr_url    = /https?:\/\/xdr\.[a-z0-9]+\.sentinelone\.net/

        // Visibility Enhanced Key variable names
        $vek_var1   = /VISIBILITY[_\.]?(?:ENHANCED[_\.]?)?KEY\s*=\s*['"]?[A-Za-z0-9+\/=]{50,}['"]?/  nocase
        $vek_var2   = /S1[_\.]?VEK\s*=\s*['"]?[A-Za-z0-9+\/=]{50,}['"]?/  nocase

    condition:
        $xdr_url or any of ($vek_var*)
}
