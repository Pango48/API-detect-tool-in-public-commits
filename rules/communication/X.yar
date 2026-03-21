/*
 * YARA Rules: X (formerly Twitter) API Credentials
 *
 * Author      : BERTON Jules - MORETTI Enzo
 * Date        : 19-03-2026
 * Version     : 1.0
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
        author         = "BERTON Jules - MORETTI Enzo"
        date           = "19-03-2026"
        version        = "1.0"
        reference      = "https://developer.x.com/en/docs/authentication/oauth-2-0/bearer-tokens"
        confidence     = "HIGH"
        false_positive = "LOW"
        severity       = "HIGH"
        tags           = "twitter,x,oauth2,bearer-token"

    strings:
        // Bearer token pattern — always starts with many 'A's (base64 of null bytes)
        $bearer = /AAAAAAAAAAAAAAAAAAAAAA[A-Za-z0-9%+\/=_\-]{50,}/

        // Common variable name anchors
        $var1   = /bearer[_.]?token[ \t]*[=:"']{1,3}[ \t]*['"]?AAAAAAAAAAAAAAA/ nocase
        $var2   = /TWITTER[_.]BEARER[_.]TOKEN[ \t]*=[ \t]*['"]?AAAAAAAAAAAAAAA/

    condition:
        $bearer or any of ($var*)
}


rule Twitter_X_API_Consumer_Keys
{
    meta:
        description    = "Detects X/Twitter OAuth 1.0a Consumer Key and Secret pairs"
        author         = "BERTON Jules - MORETTI Enzo"
        date           = "19-03-2026"
        version        = "1.0"
        reference      = "https://developer.x.com/en/docs/authentication/oauth-1-0a"
        confidence     = "MEDIUM"
        false_positive = "MEDIUM"
        severity       = "HIGH"
        tags           = "twitter,x,oauth1,consumer-key,api-key"

    strings:
        // Consumer Key / API Key — TWITTER variant
        $api_key1a  = /TWITTER[_.]API[_.]KEY[ \t]*=[ \t]*['"]?[A-Za-z0-9]{25}['"]?/ nocase
        $api_key1b  = /TWITTER[_.]CONSUMER[_.]KEY[ \t]*=[ \t]*['"]?[A-Za-z0-9]{25}['"]?/ nocase
        // Consumer Key / API Key — X variant
        $api_key1c  = /X[_.]API[_.]KEY[ \t]*=[ \t]*['"]?[A-Za-z0-9]{25}['"]?/ nocase
        $api_key1d  = /X[_.]CONSUMER[_.]KEY[ \t]*=[ \t]*['"]?[A-Za-z0-9]{25}['"]?/ nocase
        // Generic config pattern
        $api_key2   = /consumer[_.]key[ \t]*[=:"']{1,3}[ \t]*['"]?[A-Za-z0-9]{25}['"]?/ nocase

        // Consumer Secret / API Secret — TWITTER variant
        $api_sec1a  = /TWITTER[_.]API[_.]SECRET[ \t]*=[ \t]*['"]?[A-Za-z0-9]{50}['"]?/ nocase
        $api_sec1b  = /TWITTER[_.]CONSUMER[_.]SECRET[ \t]*=[ \t]*['"]?[A-Za-z0-9]{50}['"]?/ nocase
        // Consumer Secret / API Secret — X variant
        $api_sec1c  = /X[_.]API[_.]SECRET[ \t]*=[ \t]*['"]?[A-Za-z0-9]{50}['"]?/ nocase
        $api_sec1d  = /X[_.]CONSUMER[_.]SECRET[ \t]*=[ \t]*['"]?[A-Za-z0-9]{50}['"]?/ nocase
        // Generic config pattern
        $api_sec2   = /consumer[_.]secret[ \t]*[=:"']{1,3}[ \t]*['"]?[A-Za-z0-9]{50}['"]?/ nocase

    condition:
        any of them
}


rule Twitter_X_Access_Token
{
    meta:
        description    = "Detects X/Twitter OAuth 1.0a Access Token and Access Token Secret"
        author         = "BERTON Jules - MORETTI Enzo"
        date           = "19-03-2026"
        version        = "1.0"
        reference      = "https://developer.x.com/en/docs/authentication/oauth-1-0a/obtaining-user-access-tokens"
        confidence     = "MEDIUM"
        false_positive = "MEDIUM"
        severity       = "HIGH"
        tags           = "twitter,x,oauth1,access-token"

    strings:
        // Access token — TWITTER variant
        $acc_tok1a  = /TWITTER[_.]ACCESS[_.]TOKEN[ \t]*=[ \t]*['"]?[0-9]+-[A-Za-z0-9]{30,}['"]?/ nocase
        // Access token — X variant
        $acc_tok1b  = /X[_.]ACCESS[_.]TOKEN[ \t]*=[ \t]*['"]?[0-9]+-[A-Za-z0-9]{30,}['"]?/ nocase
        // Generic config pattern
        $acc_tok2   = /access[_.]token[ \t]*[=:"']{1,3}[ \t]*['"]?[0-9]{6,}-[A-Za-z0-9]{30,}['"]?/ nocase

        // Access Token Secret — TWITTER variant
        $acc_sec1a  = /TWITTER[_.]ACCESS[_.]TOKEN[_.]SECRET[ \t]*=[ \t]*['"]?[A-Za-z0-9]{45}['"]?/ nocase
        // Access Token Secret — X variant
        $acc_sec1b  = /X[_.]ACCESS[_.]TOKEN[_.]SECRET[ \t]*=[ \t]*['"]?[A-Za-z0-9]{45}['"]?/ nocase
        // Generic config pattern
        $acc_sec2   = /access[_.]token[_.]secret[ \t]*[=:"']{1,3}[ \t]*['"]?[A-Za-z0-9]{45}['"]?/ nocase

    condition:
        any of them
}
