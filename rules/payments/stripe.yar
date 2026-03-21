/*
 * YARA Rules: Stripe Credentials
 *
 * Author      : BERTON Jules - MORETTI Enzo
 * Date        : 19-03-2026
 * Version     : 1.0
 * Reference   : https://stripe.com/docs/keys
 *               https://stripe.com/docs/webhooks/signatures
 *               https://stripe.com/docs/connect/oauth-reference
 *
 * Coverage:
 *   - Stripe Secret API keys (sk_live_, sk_test_)
 *   - Stripe Restricted keys (rk_live_, rk_test_)
 *   - Stripe Publishable keys (pk_live_, pk_test_)
 *   - Stripe Webhook endpoint signing secrets (whsec_)
 *   - Stripe Connect OAuth client secrets (ca_ prefix)
 */

rule Stripe_Secret_Key
{
    meta:
        description    = "Detects Stripe Secret API keys for live and test environments"
        author         = "BERTON Jules - MORETTI Enzo"
        date           = "2026-03-19"
        version        = "1.0"
        reference      = "https://stripe.com/docs/keys"
        confidence     = "HIGH"
        false_positive = "LOW"
        severity       = "CRITICAL"
        tags           = "stripe,api-key,secret-key,payment"

    strings:
        $sk_live = /sk_live_[A-Za-z0-9]{24}/
        $sk_test = /sk_test_[A-Za-z0-9]{24}/

    condition:
        any of them
}


rule Stripe_Restricted_Key
{
    meta:
        description    = "Detects Stripe Restricted API keys (scoped API keys) for live and test environments"
        author         = "BERTON Jules - MORETTI Enzo"
        date           = "2026-03-19"
        version        = "1.0"
        reference      = "https://stripe.com/docs/keys#limit-access"
        confidence     = "HIGH"
        false_positive = "LOW"
        severity       = "HIGH"
        tags           = "stripe,restricted-key,api-key,payment"

    strings:
        $rk_live = /rk_live_[A-Za-z0-9]{24}/
        $rk_test = /rk_test_[A-Za-z0-9]{24}/

    condition:
        any of them
}


rule Stripe_Publishable_Key
{
    meta:
        description    = "Detects Stripe Publishable keys — low severity alone but signals Stripe usage and may co-occur with secret keys"
        author         = "BERTON Jules - MORETTI Enzo"
        date           = "2026-03-19"
        version        = "1.0"
        reference      = "https://stripe.com/docs/keys"
        confidence     = "HIGH"
        false_positive = "LOW"
        severity       = "LOW"
        tags           = "stripe,publishable-key,api-key,payment"

    strings:
        $pk_live = /pk_live_[A-Za-z0-9]{24}/
        $pk_test = /pk_test_[A-Za-z0-9]{24}/

    condition:
        any of them
}


rule Stripe_Webhook_Signing_Secret
{
    meta:
        description    = "Detects Stripe Webhook endpoint signing secrets (whsec_) — allows forging verified webhook events"
        author         = "BERTON Jules - MORETTI Enzo"
        date           = "2026-03-19"
        version        = "1.0"
        reference      = "https://stripe.com/docs/webhooks/signatures"
        confidence     = "HIGH"
        false_positive = "LOW"
        severity       = "HIGH"
        tags           = "stripe,webhook,signing-secret,payment"

    strings:
        $whsec = /whsec_[A-Za-z0-9+\/=]{32,64}/

    condition:
        $whsec
}


rule Stripe_Connect_OAuth_Secret
{
    meta:
        description    = "Detects Stripe Connect OAuth client secrets and account identifiers used in platform integrations"
        author         = "BERTON Jules - MORETTI Enzo"
        date           = "2026-03-19"
        version        = "1.0"
        reference      = "https://stripe.com/docs/connect/oauth-reference"
        confidence     = "MEDIUM"
        false_positive = "MEDIUM"
        severity       = "HIGH"
        tags           = "stripe,connect,oauth,client-secret,payment"

    strings:
        // Connect account identifier: ca_ + 24 base62 chars
        $ca_id = /ca_[A-Za-z0-9]{24}/

        // stripe_connect_client_secret (all three infixes)
        $ctx_a = /stripe[_\-.]connect[_\-.]client[_\-.]secret[ \t]*[=:"']{1,3}[ \t]*['"]?[A-Za-z0-9_]{20,}['"]?/ nocase
        // stripe_connect_secret (connect infix, no client)
        $ctx_b = /stripe[_\-.]connect[_\-.]secret[ \t]*[=:"']{1,3}[ \t]*['"]?[A-Za-z0-9_]{20,}['"]?/ nocase
        // stripe_client_secret (client infix, no connect)
        $ctx_c = /stripe[_\-.]client[_\-.]secret[ \t]*[=:"']{1,3}[ \t]*['"]?[A-Za-z0-9_]{20,}['"]?/ nocase
        // stripe_secret (no infixes)
        $ctx_d = /stripe[_\-.]secret[ \t]*[=:"']{1,3}[ \t]*['"]?[A-Za-z0-9_]{20,}['"]?/ nocase

    condition:
        $ca_id or $ctx_a or $ctx_b or $ctx_c or $ctx_d
}
