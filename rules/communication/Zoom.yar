/*
 * YARA Rules: Zoom API Credentials
 *
 * Date        : 19-03-2026
 * Version     : 1.0
 * Reference   : https://developers.zoom.us/docs/internal-apps/s2s-oauth/
 *
 * Coverage:
 *   - Zoom Server-to-Server (S2S) OAuth credentials (Account ID + Client ID + Client Secret)
 *   - Zoom OAuth access tokens
 *   - Zoom legacy JWT tokens (deprecated June 2023, still found in the wild)
 *   - Zoom webhook secret tokens
 *
 * Architecture notes:
 *   Zoom deprecated JWT app type in June 2023. Credentials from JWT apps are
 *   still found in leaked code and repos. They should still be detected.
 *
 *   S2S OAuth uses three credentials stored together:
 *     ZOOM_ACCOUNT_ID   : ~22 chars alphanumeric
 *     ZOOM_CLIENT_ID    : ~22 chars alphanumeric
 *     ZOOM_CLIENT_SECRET: ~32 chars alphanumeric
 *   All three appearing together is a critical finding.
 *
 *   Zoom access tokens are short-lived JWTs (~1 hour), but the credentials
 *   used to generate them (client secret) are long-lived and high-value.
 */

rule Zoom_S2S_OAuth_Credentials
{
    meta:
        description    = "Detects Zoom Server-to-Server OAuth credentials (Account ID + Client ID + Secret)"
        author         = "yara-apikey-rules"
        date           = "2025-03-03"
        version        = "1.0"
        reference      = "https://developers.zoom.us/docs/internal-apps/s2s-oauth/"
        confidence     = "HIGH"
        false_positive = "LOW"
        severity       = "CRITICAL"
        tags           = "zoom,s2s-oauth,client-secret,account-id"

    strings:
        // All three credentials typically appear together in .env files
        $account_id     = /ZOOM_ACCOUNT_ID\s*=\s*['"]?[A-Za-z0-9_\-]{22}['"]?/
        $client_id      = /ZOOM_CLIENT_ID\s*=\s*['"]?[A-Za-z0-9_\-]{22}['"]?/
        $client_secret  = /ZOOM_CLIENT_SECRET\s*=\s*['"]?[A-Za-z0-9_\-]{32}['"]?/

        // Lowercase variants
        $client_sec2    = /zoom[_\.]?client[_\.]?secret\s*[=:"']{1,3}\s*['"]?[A-Za-z0-9_\-]{32}['"]?/  nocase

    condition:
        // High confidence: all three present (typical .env leak)
        ($account_id and $client_id and $client_secret)
        or
        // Medium confidence: just the secret with a named anchor
        ($client_secret or $client_sec2)
}


rule Zoom_Legacy_JWT_Credentials
{
    meta:
        description    = "Detects Zoom legacy JWT API Key and Secret (deprecated June 2023, still found in old repos)"
        author         = "yara-apikey-rules"
        date           = "2025-03-03"
        version        = "1.0"
        reference      = "https://developers.zoom.us/docs/internal-apps/jwt/"
        confidence     = "HIGH"
        false_positive = "LOW"
        severity       = "HIGH"
        tags           = "zoom,jwt,legacy,api-key,deprecated"

    strings:
        // Zoom JWT API key (~22 alphanumeric chars)
        $jwt_key1   = /ZOOM[_\.]?(?:JWT[_\.]?)?API[_\.]?KEY\s*=\s*['"]?[A-Za-z0-9_\-]{22}['"]?/  nocase
        $jwt_key2   = /zoom[_\.]?api[_\.]?key\s*[=:"']{1,3}\s*['"]?[A-Za-z0-9_\-]{22}['"]?/  nocase

        // Zoom JWT API secret (~32 alphanumeric chars)
        $jwt_sec1   = /ZOOM[_\.]?(?:JWT[_\.]?)?API[_\.]?SECRET\s*=\s*['"]?[A-Za-z0-9_\-]{32}['"]?/  nocase
        $jwt_sec2   = /zoom[_\.]?api[_\.]?secret\s*[=:"']{1,3}\s*['"]?[A-Za-z0-9_\-]{32}['"]?/  nocase

    condition:
        any of them
}


rule Zoom_OAuth_Access_Token
{
    meta:
        description    = "Detects Zoom OAuth access tokens in Authorization headers or config files"
        author         = "yara-apikey-rules"
        date           = "2025-03-03"
        version        = "1.0"
        confidence     = "MEDIUM"
        false_positive = "MEDIUM"
        severity       = "MEDIUM"
        tags           = "zoom,oauth,access-token"

    strings:
        // Access token variable anchor — token itself is a JWT (~200+ chars)
        $var1   = /ZOOM[_\.]?ACCESS[_\.]?TOKEN\s*=\s*['"]?[A-Za-z0-9_\-]{20,}['"]?/  nocase
        $var2   = /zoom[_\.]?token\s*[=:"']{1,3}\s*['"]?[A-Za-z0-9_\-]{20,}['"]?/  nocase

        // API endpoint anchor + Bearer auth header
        $api    = "https://api.zoom.us/v2/"
        $bearer = /Authorization:\s*Bearer\s+[A-Za-z0-9_\-\.]{20,}/  nocase

    condition:
        ($api and $bearer) or any of ($var*)
}


rule Zoom_Webhook_Secret_Token
{
    meta:
        description    = "Detects Zoom Webhook Secret Tokens used to validate webhook event payloads"
        author         = "yara-apikey-rules"
        date           = "2025-03-03"
        version        = "1.0"
        reference      = "https://developers.zoom.us/docs/api/rest/webhook-reference/"
        confidence     = "MEDIUM"
        false_positive = "LOW"
        severity       = "MEDIUM"
        tags           = "zoom,webhook,secret-token"

    strings:
        $var1 = /ZOOM[_\.]?WEBHOOK[_\.]?SECRET(?:[_\.]?TOKEN)?\s*=\s*['"]?[A-Za-z0-9_\-]{32,}['"]?/  nocase
        $var2 = /zoom[_\.]?webhook[_\.]?secret\s*[=:"']{1,3}\s*['"]?[A-Za-z0-9_\-]{32,}['"]?/  nocase

    condition:
        any of them
}
