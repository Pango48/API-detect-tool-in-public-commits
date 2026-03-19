/*
 * YARA Rules: Outlook / Microsoft Mail Credentials
 *
 * Date        : 19-03-2026
 * Version     : 1.0
 * Reference   : https://learn.microsoft.com/en-us/graph/auth/
 *               https://learn.microsoft.com/en-us/graph/auth-v2-user
 *
 * Coverage:
 *   - Microsoft Graph / Outlook OAuth2 refresh tokens (OAAABAAAAi prefix)
 *   - Outlook / Office365 SMTP credentials
 *   - Microsoft Graph API tokens with mail scope
 *
 * Notes:
 *   Microsoft Graph refresh tokens start with "OAAABAAAAi" — this prefix
 *   is visible in official Microsoft documentation examples and is stable
 *   across tenants. These tokens are long-lived and grant broad access
 *   to the user's mailbox and calendar.
 *
 *   Office365 SMTP still widely used in legacy apps and automation scripts.
 *   smtp.office365.com, smtp.live.com and smtp.hotmail.com are the three
 *   main hostnames to anchor on.
 */

rule Outlook_Microsoft_Graph_Refresh_Token
{
    meta:
        description    = "Detects Microsoft Graph / Outlook OAuth2 refresh tokens (OAAABAAAAi prefix)"
        author         = "yara-apikey-rules"
        date           = "2025-03-03"
        version        = "1.0"
        reference      = "https://learn.microsoft.com/en-us/graph/auth-v2-user"
        confidence     = "HIGH"
        false_positive = "LOW"
        severity       = "CRITICAL"
        tags           = "outlook,microsoft,graph-api,oauth2,refresh-token"

    strings:
        // Microsoft Graph refresh tokens start with this prefix (documented in MSFT examples)
        $refresh_tok  = /OAAABAAAAi[A-Za-z0-9\._\-]{60,}/

        // Variable name anchors
        $var1         = /refresh[_\.]?token\s*[=:"']{1,3}\s*['"]?OAAABAAAAi[A-Za-z0-9\._\-]{30,}['"]?/  nocase
        $var2         = /MICROSOFT[_\.]?(?:GRAPH[_\.]?)?REFRESH[_\.]?TOKEN\s*=\s*['"]?OAAABAAAAi/  nocase

    condition:
        $refresh_tok or any of ($var*)
}


rule Outlook_SMTP_Credentials
{
    meta:
        description    = "Detects Outlook/Office365 SMTP credentials in config files"
        author         = "yara-apikey-rules"
        date           = "2025-03-03"
        version        = "1.0"
        confidence     = "MEDIUM"
        false_positive = "MEDIUM"
        severity       = "HIGH"
        tags           = "outlook,office365,smtp,credentials"

    strings:
        // SMTP host anchors for Outlook/O365
        $smtp_outlook  = "smtp.office365.com"
        $smtp_live     = "smtp.live.com"
        $smtp_hotmail  = "smtp.hotmail.com"

        // Password field nearby
        $pass_field    = /password\s*[=:"']{1,3}\s*['"]?[A-Za-z0-9!@#$%^&*]{8,}['"]?/  nocase

    condition:
        any of ($smtp_*) and $pass_field
}


rule Microsoft_Graph_Mail_Scope_Token
{
    meta:
        description    = "Detects Microsoft Graph API access tokens with mail scope in Authorization headers or config"
        author         = "yara-apikey-rules"
        date           = "2025-03-03"
        version        = "1.0"
        confidence     = "MEDIUM"
        false_positive = "MEDIUM"
        severity       = "HIGH"
        tags           = "outlook,microsoft,graph-api,mail,access-token"

    strings:
        // Graph API endpoint for mail
        $graph_mail   = "https://graph.microsoft.com/v1.0/me/sendMail"
        $graph_mail2  = "https://graph.microsoft.com/v1.0/users/"

        // Scope indicators for mail access
        $scope_mail   = "https://outlook.office.com/Mail.Send"
        $scope_mail2  = "https://graph.microsoft.com/mail.read"

        // Client credentials in config
        $client_sec   = /client[_\.]?secret\s*[=:"']{1,3}\s*['"]?[A-Za-z0-9\.\-_~]{34,42}['"]?/  nocase

    condition:
        ($graph_mail or $graph_mail2) and ($scope_mail or $scope_mail2 or $client_sec)
}
