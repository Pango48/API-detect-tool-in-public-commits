/*
 * YARA Rules: Discord Credentials
 *
 * Date        : 19-03-2026
 * Version     : 1.0
 * Reference   : https://discord.com/developers/docs
 *
 * Coverage:
 *   - Discord Bot Tokens (user token + MFA token)
 *   - Discord Webhook URLs
 *   - Discord OAuth2 Client Secret
 *
 * Token structure (bot token):
 *   Part 1 : Base64-encoded user/bot ID     (~24 chars, [\w-])
 *   Part 2 : Timestamp                       (6 chars,   [\w-])
 *   Part 3 : HMAC                            (27 chars,  [\w-])
 *   Separator: dot (.)
 *
 * Malware regex used in the wild (K7 Labs research):
 *   r"[\w-]{24}\.[\w-]{6}\.[\w-]{27}"
 *   r"mfa\.[\w-]{84}"
 */

rule Discord_Bot_Token
{
    meta:
        description    = "Detects Discord bot tokens (standard and MFA variants)"
        author         = "yara-apikey-rules"
        date           = "2025-03-03"
        version        = "1.0"
        reference      = "https://discord.com/developers/docs/topics/oauth2"
        confidence     = "HIGH"
        false_positive = "LOW"
        severity       = "CRITICAL"
        tags           = "discord,bot-token,credential-leak"

    strings:
        // Standard bot token: base64_id.timestamp.hmac
        $bot_token  = /[\w\-]{24}\.[\w\-]{6}\.[\w\-]{27}/

        // MFA token variant (used in user account takeover malware)
        $mfa_token  = /mfa\.[\w\-]{84}/

    condition:
        any of them
}


rule Discord_Webhook_URL
{
    meta:
        description    = "Detects Discord Incoming Webhook URLs (used for C2 in malware and for notification abuse)"
        author         = "yara-apikey-rules"
        date           = "2025-03-03"
        version        = "1.0"
        reference      = "https://discord.com/developers/docs/resources/webhook"
        confidence     = "HIGH"
        false_positive = "LOW"
        severity       = "HIGH"
        tags           = "discord,webhook,c2,exfiltration"

    strings:
        // Standard webhook URL — discord.com and discordapp.com variants
        // Also matches canary and ptb environments
        $webhook_main  = /https:\/\/(?:(?:canary|ptb)\.)?discord(?:app)?\.com\/api(?:\/v\d+)?\/webhooks\/\d+\/[\w\-]+/

    condition:
        $webhook_main
}


rule Discord_OAuth2_Client_Secret
{
    meta:
        description    = "Detects Discord OAuth2 application client secrets in config or env files"
        author         = "yara-apikey-rules"
        date           = "2025-03-03"
        version        = "1.0"
        confidence     = "MEDIUM"
        false_positive = "MEDIUM"
        severity       = "HIGH"
        tags           = "discord,oauth2,client-secret"

    strings:
        // Environment variable or config file patterns
        $var1 = /DISCORD[_\.]?(?:CLIENT[_\.]?)?SECRET\s*=\s*['"]?[A-Za-z0-9_\-]{32,}['"]?/  nocase
        $var2 = /discord[_\.]?client[_\.]?secret\s*[=:"']{1,3}\s*['"]?[A-Za-z0-9_\-]{32,}['"]?/  nocase

        // JSON config pattern
        $json = /"client_secret"\s*:\s*"[A-Za-z0-9_\-]{32,}"/

    condition:
        any of them
}

