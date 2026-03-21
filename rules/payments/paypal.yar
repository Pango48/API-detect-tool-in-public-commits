/*
 * YARA Rules: PayPal Credentials
 *
 * Author      : BERTON Jules - MORETTI Enzo
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
 */

rule PayPal_REST_API_Client_Secret
{
    meta:
        description    = "Detects PayPal REST API Client Secret — sufficient to obtain a bearer token with full API access"
        author         = "BERTON Jules - MORETTI Enzo"
        date           = "2026-03-19"
        version        = "1.0"
        reference      = "https://developer.paypal.com/api/rest/authentication/"
        confidence     = "MEDIUM"
        false_positive = "MEDIUM"
        severity       = "CRITICAL"
        tags           = "paypal,rest-api,client-secret,payment"

    strings:
        // paypal_client_secret — with client infix
        $secret1a    = /paypal[_\-.]client[_\-.]secret[ \t]*[=:"']{1,3}[ \t]*['"]?[A-Za-z0-9_\-]{30,80}['"]?/ nocase
        // paypal_secret — without client infix
        $secret1b    = /paypal[_\-.]secret[ \t]*[=:"']{1,3}[ \t]*['"]?[A-Za-z0-9_\-]{30,80}['"]?/ nocase
        // PAYPAL_CLIENT_SECRET — with CLIENT infix
        $secret2a    = /PAYPAL[_.]CLIENT[_.]SECRET[ \t]*=[ \t]*['"]?[A-Za-z0-9_\-]{30,80}['"]?/ nocase
        // PAYPAL_SECRET — without CLIENT infix
        $secret2b    = /PAYPAL[_.]SECRET[ \t]*=[ \t]*['"]?[A-Za-z0-9_\-]{30,80}['"]?/ nocase

        // JSON config — paypal_client_secret key
        $json_sec_pp = /"paypal_client_secret"[ \t]*:[ \t]*"[A-Za-z0-9_\-]{30,80}"/
        // JSON config — client_secret key (generic)
        $json_sec    = /"client_secret"[ \t]*:[ \t]*"[A-Za-z0-9_\-]{30,80}"/

    condition:
        any of them
}


rule PayPal_REST_API_Full_Credentials
{
    meta:
        description    = "Detects PayPal REST API Client ID and Client Secret present together in the same file — high-confidence leak"
        author         = "BERTON Jules - MORETTI Enzo"
        date           = "2026-03-19"
        version        = "1.0"
        reference      = "https://developer.paypal.com/api/rest/authentication/"
        confidence     = "HIGH"
        false_positive = "LOW"
        severity       = "CRITICAL"
        tags           = "paypal,rest-api,client-id,client-secret,payment"

    strings:
        // Client ID anchors
        $client_id1  = /paypal[_\-.]client[_\-.]id[ \t]*[=:"']{1,3}[ \t]*['"]?[A-Za-z0-9_\-]{50,100}['"]?/ nocase
        $client_id2  = /PAYPAL[_.]CLIENT[_.]ID[ \t]*=[ \t]*['"]?[A-Za-z0-9_\-]{50,100}['"]?/ nocase

        // Client Secret anchors — with CLIENT infix
        $secret1a    = /paypal[_\-.]client[_\-.]secret[ \t]*[=:"']{1,3}[ \t]*['"]?[A-Za-z0-9_\-]{30,80}['"]?/ nocase
        // Client Secret anchors — without CLIENT infix
        $secret1b    = /paypal[_\-.]secret[ \t]*[=:"']{1,3}[ \t]*['"]?[A-Za-z0-9_\-]{30,80}['"]?/ nocase
        $secret2a    = /PAYPAL[_.]CLIENT[_.]SECRET[ \t]*=[ \t]*['"]?[A-Za-z0-9_\-]{30,80}['"]?/ nocase
        $secret2b    = /PAYPAL[_.]SECRET[ \t]*=[ \t]*['"]?[A-Za-z0-9_\-]{30,80}['"]?/ nocase

        // JSON pair — paypal_ prefixed keys
        $json_id_pp  = /"paypal_client_id"[ \t]*:[ \t]*"[A-Za-z0-9_\-]{50,100}"/
        // JSON pair — generic keys
        $json_id     = /"client_id"[ \t]*:[ \t]*"[A-Za-z0-9_\-]{50,100}"/
        $json_sec_pp = /"paypal_client_secret"[ \t]*:[ \t]*"[A-Za-z0-9_\-]{30,80}"/
        $json_sec    = /"client_secret"[ \t]*:[ \t]*"[A-Za-z0-9_\-]{30,80}"/

    condition:
        (($client_id1 or $client_id2) and ($secret1a or $secret1b or $secret2a or $secret2b))
        or (($json_id_pp or $json_id) and ($json_sec_pp or $json_sec))
}


rule PayPal_Sandbox_Credentials
{
    meta:
        description    = "Detects PayPal Sandbox API credentials — lower severity but often reused in production and reveals payment architecture"
        author         = "BERTON Jules - MORETTI Enzo"
        date           = "2026-03-19"
        version        = "1.0"
        reference      = "https://developer.paypal.com/tools/sandbox/accounts/"
        confidence     = "MEDIUM"
        false_positive = "MEDIUM"
        severity       = "MEDIUM"
        tags           = "paypal,sandbox,credentials,payment"

    strings:
        // Sandbox mode flag — PAYPAL_MODE=sandbox
        $sandbox_mode_m  = /PAYPAL[_.]MODE[ \t]*=[ \t]*['"]?sandbox['"]?/ nocase
        // Sandbox env flag — PAYPAL_ENV=sandbox
        $sandbox_mode_e  = /PAYPAL[_.]ENV[ \t]*=[ \t]*['"]?sandbox['"]?/ nocase
        // Sandbox environment flag — PAYPAL_ENVIRONMENT=sandbox
        $sandbox_mode_ev = /PAYPAL[_.]ENVIRONMENT[ \t]*=[ \t]*['"]?sandbox['"]?/ nocase

        // Sandbox API endpoint reference
        $sandbox_url     = "https://api-m.sandbox.paypal.com"

        // Sandbox-specific secret variable — with client infix
        $sandbox_sec_a   = /paypal[_\-.]sandbox[_\-.]client[_\-.]secret[ \t]*[=:"']{1,3}[ \t]*['"]?[A-Za-z0-9_\-]{30,80}['"]?/ nocase
        // Sandbox-specific secret variable — without client infix
        $sandbox_sec_b   = /paypal[_\-.]sandbox[_\-.]secret[ \t]*[=:"']{1,3}[ \t]*['"]?[A-Za-z0-9_\-]{30,80}['"]?/ nocase

    condition:
        ($sandbox_sec_a or $sandbox_sec_b)
        or (($sandbox_mode_m or $sandbox_mode_e or $sandbox_mode_ev) and $sandbox_url)
}


rule PayPal_IPN_Token
{
    meta:
        description    = "Detects PayPal Instant Payment Notification (IPN) tokens — allows forging payment notifications"
        author         = "BERTON Jules - MORETTI Enzo"
        date           = "2026-03-19"
        version        = "1.0"
        reference      = "https://developer.paypal.com/api/nvp-soap/ipn/"
        confidence     = "MEDIUM"
        false_positive = "MEDIUM"
        severity       = "HIGH"
        tags           = "paypal,ipn,token,payment"

    strings:
        // IPN token anchor
        $ipn_token = /paypal[_\-.]ipn[_\-.]token[ \t]*[=:"']{1,3}[ \t]*['"]?[A-Za-z0-9]{20,}['"]?/ nocase

        // IPN verification URL reference alongside a token value
        $ipn_url   = "https://ipnpb.paypal.com/cgi-bin/webscr"

    condition:
        $ipn_token or $ipn_url
}


rule PayPal_Webhook_ID
{
    meta:
        description    = "Detects PayPal Webhook IDs — used to validate inbound webhook events; leaking allows bypass of signature verification"
        author         = "BERTON Jules - MORETTI Enzo"
        date           = "2026-03-19"
        version        = "1.0"
        reference      = "https://developer.paypal.com/api/webhooks/v1/"
        confidence     = "MEDIUM"
        false_positive = "MEDIUM"
        severity       = "HIGH"
        tags           = "paypal,webhook,webhook-id,payment"

    strings:
        // Webhook ID in named config
        $webhook_id  = /paypal[_\-.]webhook[_\-.]id[ \t]*[=:"']{1,3}[ \t]*['"]?[A-Z0-9]{17}['"]?/ nocase
        $json_hook   = /"webhook_id"[ \t]*:[ \t]*"[A-Z0-9]{17}"/

    condition:
        any of them
}
