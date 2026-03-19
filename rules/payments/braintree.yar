/*
 * YARA Rules: Braintree Credentials
 *
 * Author      : BERTON Jules - MORETTI Enzo
 * Date        : 19-03-2026
 * Version     : 1.0
 * Reference   : https://developer.paypal.com/braintree/docs/reference/general/authentication/
 *               https://developer.paypal.com/braintree/docs/guides/authorization/tokenization-key
 *               https://developer.paypal.com/braintree/docs/start/hello-server/
 *
 * Coverage:
 *   - Braintree Private Key (server-side transaction authority)
 *   - Braintree full credential triad (Merchant ID + Public Key + Private Key)
 *   - Braintree Tokenization Keys (client-side, sandbox & production)
 *   - Braintree SDK gateway instantiation with hardcoded credentials
 *
 * Architecture notes:
 *   Braintree (a PayPal subsidiary) uses a tripartite credential model:
 *   Merchant ID + Public Key + Private Key. The private key alone is sufficient
 *   to perform server-side transactions (charges, refunds, vaults) without
 *   additional authentication. Keys are short (~16–32 lowercase hex chars) and
 *   appear in strongly-named configuration fields across multiple SDK languages
 *   (Ruby, Python, PHP, Node.js, Java, .NET).
 *   Tokenization Keys follow a structured format:
 *   <environment>_<8-char-merchant-id>_<16-char-public-key>
 *   and are used for client-side card tokenization.
 */

rule Braintree_Private_Key
{
    meta:
        description    = "Detects Braintree Private Keys — sufficient alone to perform server-side payment transactions"
        author         = "BERTON Jules - MORETTI Enzo"
        date           = "2026-03-19"
        version        = "1.0"
        reference      = "https://developer.paypal.com/braintree/docs/reference/general/authentication/"
        confidence     = "HIGH"
        false_positive = "LOW"
        severity       = "CRITICAL"
        tags           = "braintree,private-key,payment,paypal"

    strings:
        // Environment variable / config file anchor
        $var1 = /braintree[_\-\.]?private[_\-\.]?key\s*[=:"']{1,3}\s*['"]?[a-f0-9]{32}['"]?/  nocase
        $var2 = /BRAINTREE[_\.]?PRIVATE[_\.]?KEY\s*=\s*['"]?[a-f0-9]{32}['"]?/  nocase

        // JSON config
        $json = /"private_key"\s*:\s*"[a-f0-9]{32}"/

        // SDK-specific patterns
        $sdk_ruby = /:private_key\s*=>\s*['"][a-f0-9]{32}['"]/   // Ruby hash rocket
        $sdk_py   = /private_key\s*=\s*['"][a-f0-9]{32}['"]/     // Python / generic

    condition:
        any of them
}


rule Braintree_Full_Credential_Set
{
    meta:
        description    = "Detects Braintree full credential triad (Merchant ID + Public Key + Private Key) in the same file — confirmed leak"
        author         = "BERTON Jules - MORETTI Enzo"
        date           = "2026-03-19"
        version        = "1.0"
        reference      = "https://developer.paypal.com/braintree/docs/reference/general/authentication/"
        confidence     = "HIGH"
        false_positive = "LOW"
        severity       = "CRITICAL"
        tags           = "braintree,merchant-id,public-key,private-key,payment"

    strings:
        // Merchant ID: 16 lowercase alphanumeric chars
        $merchant_id = /(?:braintree[_\-\.]?)?merchant[_\-\.]?id\s*[=:"']{1,3}\s*['"]?[a-z0-9]{16}['"]?/  nocase

        // Public Key: 16 lowercase alphanumeric chars
        $public_key  = /(?:braintree[_\-\.]?)?public[_\-\.]?key\s*[=:"']{1,3}\s*['"]?[a-z0-9]{16}['"]?/  nocase

        // Private Key: 32 lowercase hex chars
        $private_key = /(?:braintree[_\-\.]?)?private[_\-\.]?key\s*[=:"']{1,3}\s*['"]?[a-f0-9]{32}['"]?/  nocase

    condition:
        // All three credentials present in the same file
        $merchant_id and $public_key and $private_key
}


rule Braintree_Tokenization_Key
{
    meta:
        description    = "Detects Braintree Tokenization Keys used for client-side card tokenization — reveals environment and merchant ID"
        author         = "BERTON Jules - MORETTI Enzo"
        date           = "2026-03-19"
        version        = "1.0"
        reference      = "https://developer.paypal.com/braintree/docs/guides/authorization/tokenization-key"
        confidence     = "HIGH"
        false_positive = "LOW"
        severity       = "MEDIUM"
        tags           = "braintree,tokenization-key,client-side,payment"

    strings:
        // Sandbox tokenization key: sandbox_<8-char>_<16-char>
        $tok_sandbox    = /sandbox_[a-z0-9]{8}_[a-z0-9]{16}/

        // Production tokenization key: production_<8-char>_<16-char>
        $tok_production = /production_[a-z0-9]{8}_[a-z0-9]{16}/

        // Config variable anchor (without value — catches any assignment)
        $ctx = /braintree[_\-\.]?tokenization[_\-\.]?key\s*[=:"']{1,3}/  nocase

    condition:
        $tok_sandbox or $tok_production or $ctx
}


rule Braintree_SDK_Gateway_With_Credentials
{
    meta:
        description    = "Detects Braintree SDK gateway instantiation with hardcoded credentials across Ruby, Python, PHP, Node.js and Java"
        author         = "BERTON Jules - MORETTI Enzo"
        date           = "2026-03-19"
        version        = "1.0"
        reference      = "https://developer.paypal.com/braintree/docs/start/hello-server/"
        confidence     = "MEDIUM"
        false_positive = "MEDIUM"
        severity       = "CRITICAL"
        tags           = "braintree,sdk,gateway,hardcoded-credentials,payment"

    strings:
        // SDK gateway constructor patterns (multi-language)
        $rb_gateway  = /Braintree::Gateway\.new\s*\(/                    // Ruby
        $py_gateway  = /braintree\.Configuration\.configure\s*\(/        // Python
        $php_gateway = /new\s+Braintree\\Gateway\s*\(/                   // PHP
        $js_gateway  = /new\s+braintree\.BraintreeGateway\s*\(/          // Node.js
        $java_gate   = /new\s+BraintreeGateway\s*\(/                     // Java / .NET

        // Inline private key value (32-char hex) co-located with a gateway call
        $priv_key = /['"]\s*[a-f0-9]{32}\s*['"]/

    condition:
        any of ($rb_gateway, $py_gateway, $php_gateway, $js_gateway, $java_gate) and $priv_key
}
