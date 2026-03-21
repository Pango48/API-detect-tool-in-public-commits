/*
 * YARA Rules: Discord Credentials
 *
 * Author      : BERTON Jules - MORETTI Enzo
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
        author         = "BERTON Jules - MORETTI Enzo"
        date           = "19-03-2026"
        version        = "1.0"
        reference      = "https://discord.com/developers/docs/topics/oauth2"
        confidence     = "HIGH"
        false_positive = "LOW"
        severity       = "CRITICAL"
        tags           = "discord,bot-token,credential-leak"
    strings:
        // Standard bot token: base64_id.timestamp.hmac
        // Note: [\w\-]{24} can be slow; consider adding a literal anchor if performance matters
        $bot_token  = /[A-Za-z0-9_\-]{24}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27}/
        // MFA token variant (used in user account takeover malware)
        $mfa_token  = /mfa\.[A-Za-z0-9_\-]{84}/
    condition:
        any of them
}

rule Discord_Webhook_URL
{
    meta:
        description    = "Detects Discord Incoming Webhook URLs (used for C2 in malware and for notification abuse)"
        author         = "BERTON Jules - MORETTI Enzo"
        date           = "19-03-2026"
        version        = "1.0"
        reference      = "https://discord.com/developers/docs/resources/webhook"
        confidence     = "HIGH"
        false_positive = "LOW"
        severity       = "HIGH"
        tags           = "discord,webhook,c2,exfiltration"
    strings:
        // Standard webhook URL — discord.com variant
        $webhook_discord  = /https:\/\/discord\.com\/api\/webhooks\/[0-9]+\/[A-Za-z0-9_\-]+/
        // discordapp.com variant
        $webhook_app      = /https:\/\/discordapp\.com\/api\/webhooks\/[0-9]+\/[A-Za-z0-9_\-]+/
        // Canary environment
        $webhook_canary   = /https:\/\/canary\.discord\.com\/api\/webhooks\/[0-9]+\/[A-Za-z0-9_\-]+/
        // PTB (Public Test Build) environment
        $webhook_ptb      = /https:\/\/ptb\.discord\.com\/api\/webhooks\/[0-9]+\/[A-Za-z0-9_\-]+/
        // Versioned API (e.g. /api/v10/webhooks/...)
        $webhook_versioned = /https:\/\/discord\.com\/api\/v[0-9]+\/webhooks\/[0-9]+\/[A-Za-z0-9_\-]+/
    condition:
        any of them
}

rule Discord_OAuth2_Client_Secret
{
    meta:
        description    = "Detects Discord OAuth2 application client secrets in config or env files"
        author         = "BERTON Jules - MORETTI Enzo"
        date           = "19-03-2026"
        version        = "1.0"
        confidence     = "MEDIUM"
        false_positive = "MEDIUM"
        severity       = "HIGH"
        tags           = "discord,oauth2,client-secret"
    strings:
        // Environment variable pattern: DISCORD_SECRET=... or DISCORD_CLIENT_SECRET=...
        $var1 = /DISCORD[_.]CLIENT[_.]SECRET[ \t]*=[ \t]*[A-Za-z0-9_\-]{32,}/ nocase
        $var2 = /DISCORD[_.]SECRET[ \t]*=[ \t]*[A-Za-z0-9_\-]{32,}/ nocase
        // YAML / TOML / INI style: discord_client_secret: "..."
        $var3 = /discord[_.]client[_.]secret[ \t]*:[ \t]*[A-Za-z0-9_\-]{32,}/ nocase
        // JSON config pattern
        $json = /"client_secret"[ \t]*:[ \t]*"[A-Za-z0-9_\-]{32,}"/
    condition:
        any of them
}
