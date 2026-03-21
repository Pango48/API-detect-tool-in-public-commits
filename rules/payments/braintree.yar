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
        $var1     = /braintree[_\-.]private[_\-.]key[ \t]*[=:"']{1,3}[ \t]*['"]?[a-f0-9]{32}['"]?/ nocase
        $var2     = /BRAINTREE[_.]PRIVATE[_.]KEY[ \t]*=[ \t]*['"]?[a-f0-9]{32}['"]?/ nocase

        // JSON config
        $json     = /"private_key"[ \t]*:[ \t]*"[a-f0-9]{32}"/

        // SDK-specific patterns
        $sdk_ruby = /:private_key[ \t]*=>[ \t]*['"][a-f0-9]{32}['"]/
        $sdk_py   = /private_key[ \t]*=[ \t]*['"][a-f0-9]{32}['"]/

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
        // Merchant ID — with braintree prefix
        $merchant_bt  = /braintree[_\-.]merchant[_\-.]id[ \t]*[=:"']{1,3}[ \t]*['"]?[a-z0-9]{16}['"]?/ nocase
        // Merchant ID — without braintree prefix
        $merchant_id  = /merchant[_\-.]id[ \t]*[=:"']{1,3}[ \t]*['"]?[a-z0-9]{16}['"]?/ nocase

        // Public Key — with braintree prefix
        $pubkey_bt    = /braintree[_\-.]public[_\-.]key[ \t]*[=:"']{1,3}[ \t]*['"]?[a-z0-9]{16}['"]?/ nocase
        // Public Key — without braintree prefix
        $public_key   = /public[_\-.]key[ \t]*[=:"']{1,3}[ \t]*['"]?[a-z0-9]{16}['"]?/ nocase

        // Private Key — with braintree prefix
        $privkey_bt   = /braintree[_\-.]private[_\-.]key[ \t]*[=:"']{1,3}[ \t]*['"]?[a-f0-9]{32}['"]?/ nocase
        // Private Key — without braintree prefix
        $private_key  = /private[_\-.]key[ \t]*[=:"']{1,3}[ \t]*['"]?[a-f0-9]{32}['"]?/ nocase

    condition:
        // All three credential types present in the same file
        ($merchant_bt or $merchant_id)
        and ($pubkey_bt or $public_key)
        and ($privkey_bt or $private_key)
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

        // Config variable anchor
        $ctx = /braintree[_\-.]tokenization[_\-.]key[ \t]*[=:"']{1,3}/ nocase

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
        $rb_gateway  = /Braintree::Gateway\.new[ \t]*\(/
        $py_gateway  = /braintree\.Configuration\.configure[ \t]*\(/
        $php_gateway = /new[ \t]+Braintree\\Gateway[ \t]*\(/
        $js_gateway  = /new[ \t]+braintree\.BraintreeGateway[ \t]*\(/
        $java_gate   = /new[ \t]+BraintreeGateway[ \t]*\(/

        // Inline private key value — anchored to avoid slow wildcard scan
        // 32-char lowercase hex string preceded by a quote
        $priv_key = /['"][a-f0-9]{32}['"]/

    condition:
        any of ($rb_gateway, $py_gateway, $php_gateway, $js_gateway, $java_gate) and $priv_key
}
