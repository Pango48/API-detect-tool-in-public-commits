/*
 * YARA Rules: X (formerly Twitter) API Credentials
 *
 * Author      : yara-apikey-rules contributors
 * Date        : 2025-03-03
 * Version     : 1.0
 * License     : MIT
 * Reference   : https://developer.x.com/en/docs/authentication
 *
 * Coverage:
 *   - OAuth 2.0 Bearer Tokens (app-only authentication)
 *   - OAuth 1.0a Consumer Keys & Secrets (API Key / API Secret)
 *   - OAuth 1.0a Access Token & Access Token Secret
 *
 * Token characteristics (from official X API docs):
 *   Bearer Token : Starts with "AAAAAAAAAAAAAAAAAAAAAA" (base64 of \x00 bytes
 *                  representing the Twitter user ID), followed by "%3A" or
 *                  alphanumeric chars. Total length ~80-110 chars.
 *   Consumer Key : ~25 alphanumeric characters
 *   Consumer Secret : ~50 alphanumeric characters
 *   Access Token  : numeric_id-alphanumeric (~50 chars total)
 *   Access Token Secret : ~45 alphanumeric characters
 *
 * Note: X/Twitter Bearer Tokens always start with multiple 'A' characters
 * because the first segment is a base64-encoded null-padded integer.
 * Example from official docs: AAAAAAAAAAAAAAAAAAAAAMLhe...
 */

rule Twitter_X_Bearer_Token
{
    meta:
        description    = "Detects X/Twitter OAuth 2.0 Bearer Tokens (app-only auth)"
        author         = "yara-apikey-rules"
        date           = "2025-03-03"
        version        = "1.0"
        reference      = "https://developer.x.com/en/docs/authentication/oauth-2-0/bearer-tokens"
        confidence     = "HIGH"
        false_positive = "LOW"
        severity       = "HIGH"
        tags           = "twitter,x,oauth2,bearer-token"

    strings:
        // Bearer token pattern — always starts with many 'A's (base64 of null bytes)
        // Followed by URL-encoded or raw characters, total length 80-120 chars
        $bearer = /AAAAAAAAAAAAAAAAAAAAAA[A-Za-z0-9%+\/=_\-]{50,}/

        // Common variable name anchors
        $var1   = /bearer[_\.]?token\s*[=:"']{1,3}\s*['"]?AAAAAAAAAAAAAAA/  nocase
        $var2   = /TWITTER[_\.]?BEARER[_\.]?TOKEN\s*=\s*['"]?AAAAAAAAAAAAAAA/

    condition:
        $bearer or any of ($var*)
}


rule Twitter_X_API_Consumer_Keys
{
    meta:
        description    = "Detects X/Twitter OAuth 1.0a Consumer Key and Secret pairs"
        author         = "yara-apikey-rules"
        date           = "2025-03-03"
        version        = "1.0"
        reference      = "https://developer.x.com/en/docs/authentication/oauth-1-0a"
        confidence     = "MEDIUM"
        false_positive = "MEDIUM"
        severity       = "HIGH"
        tags           = "twitter,x,oauth1,consumer-key,api-key"

    strings:
        // Consumer Key / API Key (25 alphanumeric chars)
        $api_key1   = /(?:TWITTER|X)[_\.]?(?:API|CONSUMER)[_\.]?KEY\s*=\s*['"]?[A-Za-z0-9]{25}['"]?/  nocase
        $api_key2   = /consumer[_\.]?key\s*[=:"']{1,3}\s*['"]?[A-Za-z0-9]{25}['"]?/  nocase

        // Consumer Secret / API Secret Key (~50 alphanumeric chars)
        $api_sec1   = /(?:TWITTER|X)[_\.]?(?:API|CONSUMER)[_\.]?SECRET\s*=\s*['"]?[A-Za-z0-9]{50}['"]?/  nocase
        $api_sec2   = /consumer[_\.]?secret\s*[=:"']{1,3}\s*['"]?[A-Za-z0-9]{50}['"]?/  nocase

    condition:
        any of them
}


rule Twitter_X_Access_Token
{
    meta:
        description    = "Detects X/Twitter OAuth 1.0a Access Token and Access Token Secret"
        author         = "yara-apikey-rules"
        date           = "2025-03-03"
        version        = "1.0"
        reference      = "https://developer.x.com/en/docs/authentication/oauth-1-0a/obtaining-user-access-tokens"
        confidence     = "MEDIUM"
        false_positive = "MEDIUM"
        severity       = "HIGH"
        tags           = "twitter,x,oauth1,access-token"

    strings:
        // Access token has format: <numeric_user_id>-<alphanumeric_string>
        $acc_tok1   = /(?:TWITTER|X)[_\.]?ACCESS[_\.]?TOKEN\s*=\s*['"]?[0-9]+-[A-Za-z0-9]{30,}['"]?/  nocase
        $acc_tok2   = /access[_\.]?token\s*[=:"']{1,3}\s*['"]?[0-9]{6,}-[A-Za-z0-9]{30,}['"]?/  nocase

        // Access Token Secret (~45 chars alphanumeric)
        $acc_sec1   = /(?:TWITTER|X)[_\.]?ACCESS[_\.]?TOKEN[_\.]?SECRET\s*=\s*['"]?[A-Za-z0-9]{45}['"]?/  nocase
        $acc_sec2   = /access[_\.]?token[_\.]?secret\s*[=:"']{1,3}\s*['"]?[A-Za-z0-9]{45}['"]?/  nocase

    condition:
        any of them
}
