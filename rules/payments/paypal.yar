/*
 * YARA Rules: PayPal Credentials
 *
 * Date        : 19-03-2026
 * Version     : 1.0
 * Reference   : https://developer.paypal.com/api/rest/authentication/
 *               https://developer.paypal.com/tools/sandbox/accounts/
 *               https://developer.paypal.com/api/webhooks/v1/
 *
 * Coverage:
 *   - PayPal REST API Client ID & Client Secret (live)
 *   - PayPal Sandbox credentials
 *   - PayPal Instant Payment Notification (IPN) tokens
 *   - PayPal Webhook IDs
 *
 * Architecture notes:
 *   PayPal REST API credentials are base62 strings of variable length without a
 *   strict prefix, making detection anchor-based (config key names + value patterns).
 *   The Client Secret alone is sufficient to obtain an OAuth 2.0 bearer token granting
 *   full API access including payment initiation, refunds, and subscription management.
 *   Sandbox credentials ending in -sandbox are lower severity individually but are
 *   often reused verbatim in production or reveal the application's payment architecture.
 *   Webhook IDs allow an attacker to bypass event signature verification, enabling
 *   fake payment confirmation injection.
 */

rule PayPal_REST_API_Client_Secret
{
    meta:
        description    = "Detects PayPal REST API Client Secret — sufficient to obtain a bearer token with full API access"
        author         = "yara-apikey-rules"
        date           = "2026-03-19"
        version        = "1.0"
        reference      = "https://developer.paypal.com/api/rest/authentication/"
        confidence     = "MEDIUM"
        false_positive = "MEDIUM"
        severity       = "CRITICAL"
        tags           = "paypal,rest-api,client-secret,payment"

    strings:
        // Env var anchor + long alphanumeric value
        $secret1 = /paypal[_\-\.]?(?:client[_\-\.]?)?secret\s*[=:"']{1,3}\s*['"]?[A-Za-z0-9_\-]{30,80}['"]?/  nocase
        $secret2 = /PAYPAL[_\.]?(?:CLIENT[_\.]?)?SECRET\s*=\s*['"]?[A-Za-z0-9_\-]{30,80}['"]?/  nocase

        // JSON config
        $json_secret = /"(?:paypal_)?client_secret"\s*:\s*"[A-Za-z0-9_\-]{30,80}"/

    condition:
        any of them
}


rule PayPal_REST_API_Full_Credentials
{
    meta:
        description    = "Detects PayPal REST API Client ID and Client Secret present together in the same file — high-confidence leak"
        author         = "yara-apikey-rules"
        date           = "2026-03-19"
        version        = "1.0"
        reference      = "https://developer.paypal.com/api/rest/authentication/"
        confidence     = "HIGH"
        false_positive = "LOW"
        severity       = "CRITICAL"
        tags           = "paypal,rest-api,client-id,client-secret,payment"

    strings:
        // Client ID anchor (50-100 char base62 value)
        $client_id1 = /paypal[_\-\.]?client[_\-\.]?id\s*[=:"']{1,3}\s*['"]?[A-Za-z0-9_\-]{50,100}['"]?/  nocase
        $client_id2 = /PAYPAL[_\.]?CLIENT[_\.]?ID\s*=\s*['"]?[A-Za-z0-9_\-]{50,100}['"]?/  nocase

        // Client Secret anchor (30-80 char base62 value)
        $secret1 = /paypal[_\-\.]?(?:client[_\-\.]?)?secret\s*[=:"']{1,3}\s*['"]?[A-Za-z0-9_\-]{30,80}['"]?/  nocase
        $secret2 = /PAYPAL[_\.]?(?:CLIENT[_\.]?)?SECRET\s*=\s*['"]?[A-Za-z0-9_\-]{30,80}['"]?/  nocase

        // JSON pair
        $json_id     = /"(?:paypal_)?client_id"\s*:\s*"[A-Za-z0-9_\-]{50,100}"/
        $json_secret = /"(?:paypal_)?client_secret"\s*:\s*"[A-Za-z0-9_\-]{30,80}"/

    condition:
        (($client_id1 or $client_id2) and ($secret1 or $secret2))
        or ($json_id and $json_secret)
}


rule PayPal_Sandbox_Credentials
{
    meta:
        description    = "Detects PayPal Sandbox API credentials — lower severity but often reused in production and reveals payment architecture"
        author         = "yara-apikey-rules"
        date           = "2026-03-19"
        version        = "1.0"
        reference      = "https://developer.paypal.com/tools/sandbox/accounts/"
        confidence     = "MEDIUM"
        false_positive = "MEDIUM"
        severity       = "MEDIUM"
        tags           = "paypal,sandbox,credentials,payment"

    strings:
        // Sandbox mode flag
        $sandbox_mode = /PAYPAL[_\.]?(?:MODE|ENV(?:IRONMENT)?)\s*=\s*['"]?sandbox['"]?/  nocase

        // Sandbox API endpoint reference (confirms sandbox context)
        $sandbox_url  = "https://api-m.sandbox.paypal.com"

        // Sandbox-specific secret variable
        $sandbox_secret = /paypal[_\-\.]?sandbox[_\-\.]?(?:client[_\-\.]?)?secret\s*[=:"']{1,3}\s*['"]?[A-Za-z0-9_\-]{30,80}['"]?/  nocase

    condition:
        $sandbox_secret or ($sandbox_mode and $sandbox_url)
}


rule PayPal_IPN_Token
{
    meta:
        description    = "Detects PayPal Instant Payment Notification (IPN) tokens — allows forging payment notifications"
        author         = "yara-apikey-rules"
        date           = "2026-03-19"
        version        = "1.0"
        reference      = "https://developer.paypal.com/api/nvp-soap/ipn/"
        confidence     = "MEDIUM"
        false_positive = "MEDIUM"
        severity       = "HIGH"
        tags           = "paypal,ipn,token,payment"

    strings:
        // IPN token anchor
        $ipn_token = /paypal[_\-\.]?ipn[_\-\.]?token\s*[=:"']{1,3}\s*['"]?[A-Za-z0-9]{20,}['"]?/  nocase

        // IPN verification URL reference alongside a token value
        $ipn_url   = "https://ipnpb.paypal.com/cgi-bin/webscr"

    condition:
        $ipn_token or $ipn_url
}


rule PayPal_Webhook_ID
{
    meta:
        description    = "Detects PayPal Webhook IDs — used to validate inbound webhook events; leaking allows bypass of signature verification"
        author         = "yara-apikey-rules"
        date           = "2026-03-19"
        version        = "1.0"
        reference      = "https://developer.paypal.com/api/webhooks/v1/"
        confidence     = "MEDIUM"
        false_positive = "MEDIUM"
        severity       = "HIGH"
        tags           = "paypal,webhook,webhook-id,payment"

    strings:
        // Webhook ID: 17 uppercase alphanumeric chars in named config
        $webhook_id  = /paypal[_\-\.]?webhook[_\-\.]?id\s*[=:"']{1,3}\s*['"]?[A-Z0-9]{17}['"]?/  nocase
        $json_hook   = /"webhook_id"\s*:\s*"[A-Z0-9]{17}"/

    condition:
        any of them
}
