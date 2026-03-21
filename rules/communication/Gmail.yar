/*
 * YARA Rules: Gmail Credentials
 *
 * Author      : BERTON Jules - MORETTI Enzo
 * Date        : 19-03-2026
 * Version     : 1.0
 * Reference   : https://developers.google.com/identity/protocols/oauth2
 *               https://developers.google.com/gmail/api/auth/about-auth
 *
 * Coverage:
 *   - Gmail OAuth2 access tokens (ya29. prefix)
 *   - Gmail OAuth2 credentials JSON file (client_secrets with mail scope)
 *   - Gmail App Passwords (16-char format, for 2FA accounts)
 *
 * Notes:
 *   Gmail access tokens always start with "ya29." — this is a stable,
 *   documented characteristic of Google OAuth2 access tokens.
 *
 *   Gmail App Passwords are 16-character lowercase strings generated
 *   for accounts with 2FA enabled. They appear in SMTP config files
 *   alongside smtp.gmail.com.
 */
rule Gmail_OAuth2_Access_Token
{
    meta:
        description    = "Detects Google/Gmail OAuth2 access tokens (ya29. prefix)"
        author         = "BERTON Jules - MORETTI Enzo"
        date           = "19-03-2026"
        version        = "1.0"
        reference      = "https://developers.google.com/identity/protocols/oauth2"
        confidence     = "HIGH"
        false_positive = "LOW"
        severity       = "HIGH"
        tags           = "gmail,google,oauth2,access-token"
    strings:
        // Google OAuth2 access tokens always start with "ya29."
        $access_token = /ya29\.[A-Za-z0-9_\-]{50,}/
    condition:
        $access_token
}

rule Gmail_OAuth2_Credentials_File
{
    meta:
        description    = "Detects Gmail OAuth2 credentials JSON with mail scope indicators"
        author         = "BERTON Jules - MORETTI Enzo"
        date           = "19-03-2026"
        version        = "1.0"
        reference      = "https://developers.google.com/gmail/api/auth/about-auth"
        confidence     = "HIGH"
        false_positive = "LOW"
        severity       = "CRITICAL"
        tags           = "gmail,google,oauth2,credentials-file"
    strings:
        // Gmail scope indicators
        $scope_gmail    = "https://mail.google.com/"
        $scope_gmail2   = "https://www.googleapis.com/auth/gmail"
        // Client secrets JSON fields
        $client_id      = /[0-9]+-[a-z0-9]+\.apps\.googleusercontent\.com/
        $client_secret  = /"client_secret"[ \t]*:[ \t]*"[A-Za-z0-9\-_]{24,}"/
        // Refresh token stored in credentials
        $refresh        = /"refresh_token"[ \t]*:[ \t]*"1\/\/[A-Za-z0-9\-_]{40,}"/
    condition:
        ($scope_gmail or $scope_gmail2) and ($client_id or $client_secret or $refresh)
}

rule Gmail_App_Password
{
    meta:
        description    = "Detects Gmail App Passwords (16-char codes for 2FA accounts) in SMTP config files"
        author         = "BERTON Jules - MORETTI Enzo"
        date           = "19-03-2026"
        version        = "1.0"
        reference      = "https://support.google.com/accounts/answer/185833"
        confidence     = "MEDIUM"
        false_positive = "MEDIUM"
        severity       = "HIGH"
        tags           = "gmail,google,app-password,smtp"
    strings:
        // App password in SMTP config (16 lowercase letters, sometimes with spaces)
        $smtp_host  = /smtp\.gmail\.com/
        $app_pass1  = /password[ \t]*[=:"']{1,3}[ \t]*['"]?[a-z]{4}[ ]?[a-z]{4}[ ]?[a-z]{4}[ ]?[a-z]{4}['"]?/ nocase

        // GMAIL_APP_PASSWORD=... variant (with APP_PASSWORD)
        $app_pass2a = /GMAIL[_.]APP[_.]PASSWORD[ \t]*=[ \t]*['"]?[a-z]{16}['"]?/ nocase
        // GMAIL_PASSWORD=... variant (without APP)
        $app_pass2b = /GMAIL[_.]PASSWORD[ \t]*=[ \t]*['"]?[a-z]{16}['"]?/ nocase
    condition:
        $smtp_host and ($app_pass1 or $app_pass2a or $app_pass2b)
}
