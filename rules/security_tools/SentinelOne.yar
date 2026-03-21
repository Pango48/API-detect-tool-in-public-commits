/*
 * YARA Rules: SentinelOne API Credentials
 *
 * Author      : BERTON Jules - MORETTI Enzo
 * Date        : 19-03-2026
 * Version     : 1.0
 * Reference   : https://usea1-partners.sentinelone.net/api-doc/
 *               https://www.ninjaone.com/docs/integrations/antivirus/sentinelone/
 *
 * Coverage:
 *   - SentinelOne Management API tokens (opaque Bearer tokens ~150-200 chars)
 *   - SentinelOne API token + management URL pairs
 *   - SentinelOne Singularity Data Lake (XDR) Visibility Enhanced Key
 *   - Service User token in config/env files
 */

rule SentinelOne_API_Token_In_Header
{
    meta:
        description    = "Detects SentinelOne API tokens in Authorization headers (ApiToken scheme)"
        author         = "BERTON Jules - MORETTI Enzo"
        date           = "19-03-2026"
        version        = "1.0"
        reference      = "https://usea1-partners.sentinelone.net/api-doc/"
        confidence     = "HIGH"
        false_positive = "LOW"
        severity       = "CRITICAL"
        tags           = "sentinelone,edr,api-token,authorization-header"

    strings:
        // SentinelOne uses "ApiToken" scheme — not "Bearer" — highly distinctive
        $apitoken_hdr = /Authorization:[ \t]*ApiToken[ \t]+[A-Za-z0-9+\/=]{50,}/ nocase

        // Also seen in curl -H form
        $curl_hdr     = /-H[ \t]+['"]Authorization:[ \t]*ApiToken[ \t]+[A-Za-z0-9+\/=]{50,}['"]/ nocase

    condition:
        any of them
}


rule SentinelOne_API_Token_In_Config
{
    meta:
        description    = "Detects SentinelOne API tokens in config files, env files, or source code"
        author         = "BERTON Jules - MORETTI Enzo"
        date           = "19-03-2026"
        version        = "1.0"
        reference      = "https://www.ninjaone.com/docs/integrations/antivirus/sentinelone/"
        confidence     = "HIGH"
        false_positive = "LOW"
        severity       = "CRITICAL"
        tags           = "sentinelone,edr,api-token,config,env"

    strings:
        // S1_API_TOKEN
        $env1         = /S1[_.]API[_.]TOKEN[ \t]*=[ \t]*['"]?[A-Za-z0-9+\/=]{50,}['"]?/ nocase

        // SENTINELONE_API_TOKEN — with API infix
        $env2a        = /SENTINELONE[_.]API[_.]TOKEN[ \t]*=[ \t]*['"]?[A-Za-z0-9+\/=]{50,}['"]?/ nocase
        // SENTINELONE_TOKEN — without API infix
        $env2b        = /SENTINELONE[_.]TOKEN[ \t]*=[ \t]*['"]?[A-Za-z0-9+\/=]{50,}['"]?/ nocase

        // SENTINELONE_API_KEY
        $env3         = /SENTINELONE[_.]API[_.]KEY[ \t]*=[ \t]*['"]?[A-Za-z0-9+\/=]{50,}['"]?/ nocase

        // JSON/YAML config — api_token key
        $json1a       = /"api[_\-]token"[ \t]*:[ \t]*"[A-Za-z0-9+\/=]{50,}"/
        // JSON/YAML config — apiToken key
        $json1b       = /"apiToken"[ \t]*:[ \t]*"[A-Za-z0-9+\/=]{50,}"/

        // Python SDK
        $sdk_py       = /SentinelOneSDK[ \t]*\(.*token[ \t]*=[ \t]*['"][A-Za-z0-9+\/=]{50,}['"]/ nocase

    condition:
        any of them
}


rule SentinelOne_Credentials_Pair
{
    meta:
        description    = "Detects SentinelOne management URL + API token pair — high confidence credential leak"
        author         = "BERTON Jules - MORETTI Enzo"
        date           = "19-03-2026"
        version        = "1.0"
        reference      = "https://docs.alertlogic.com/configure/connections/sentinelone.htm"
        confidence     = "HIGH"
        false_positive = "LOW"
        severity       = "CRITICAL"
        tags           = "sentinelone,edr,api-token,management-url,credential-pair"

    strings:
        // SentinelOne management console URL
        $mgmt_url      = /https?:\/\/[a-zA-Z0-9\-]+\.sentinelone\.net/

        // Token variable — api_token key
        $token_var_at  = /api[_\-]token[ \t]*[=:"']{1,3}[ \t]*['"]?[A-Za-z0-9+\/=]{50,}['"]?/ nocase
        // Token variable — apiToken key
        $token_var_aT  = /apiToken[ \t]*[=:"']{1,3}[ \t]*['"]?[A-Za-z0-9+\/=]{50,}['"]?/ nocase
        // Token variable — token key
        $token_var_t   = /token[ \t]*[=:"']{1,3}[ \t]*['"]?[A-Za-z0-9+\/=]{50,}['"]?/ nocase
        // Token variable — api_key key
        $token_var_ak  = /api[_\-]key[ \t]*[=:"']{1,3}[ \t]*['"]?[A-Za-z0-9+\/=]{50,}['"]?/ nocase

    condition:
        $mgmt_url and ($token_var_at or $token_var_aT or $token_var_t or $token_var_ak)
}


rule SentinelOne_XDR_Visibility_Key
{
    meta:
        description    = "Detects SentinelOne Singularity Data Lake / XDR Visibility Enhanced Key credentials"
        author         = "BERTON Jules - MORETTI Enzo"
        date           = "19-03-2026"
        version        = "1.0"
        reference      = "https://docs.synqly.com/guides/provider-configuration/sentinelone-setup"
        confidence     = "HIGH"
        false_positive = "LOW"
        severity       = "CRITICAL"
        tags           = "sentinelone,xdr,singularity,data-lake,visibility-key"

    strings:
        // XDR endpoint anchor
        $xdr_url      = /https?:\/\/xdr\.[a-z0-9]+\.sentinelone\.net/

        // VISIBILITY_ENHANCED_KEY — with ENHANCED infix
        $vek_var1a    = /VISIBILITY[_.]ENHANCED[_.]KEY[ \t]*=[ \t]*['"]?[A-Za-z0-9+\/=]{50,}['"]?/ nocase
        // VISIBILITY_KEY — without ENHANCED infix
        $vek_var1b    = /VISIBILITY[_.]KEY[ \t]*=[ \t]*['"]?[A-Za-z0-9+\/=]{50,}['"]?/ nocase

        // S1_VEK
        $vek_var2     = /S1[_.]VEK[ \t]*=[ \t]*['"]?[A-Za-z0-9+\/=]{50,}['"]?/ nocase

    condition:
        $xdr_url or $vek_var1a or $vek_var1b or $vek_var2
}
