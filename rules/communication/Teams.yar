/*
 * YARA Rules: Microsoft Teams Credentials
 *
 * Author      : BERTON Jules - MORETTI Enzo
 * Date        : 19-03-2026
 * Version     : 1.0
 * Reference   : https://learn.microsoft.com/en-us/microsoftteams/platform/messaging-extensions/api-based-secret-service-auth
 *
 * Coverage:
 *   - Teams Incoming Webhook URLs
 *   - Teams Outgoing Webhook HMAC security tokens
 *   - Microsoft Graph API tokens scoped to Teams
 *   - Power Automate / Logic App webhook URLs (used as Teams connectors)
 *   - Teams API Secret Service Auth (Message Extensions — apiSecretRegistrationId + API key)
 *
 * Architecture notes:
 *   Teams Incoming Webhooks are hosted on outlook.office.com or webhook.office.com.
 *   They follow a structured URL format with a GUID-based path.
 *   Power Automate flows exposed as webhooks use logic.azure.com URLs and
 *   include a "sig" parameter — leaking these gives full message-post capability.
 *
 *   Outgoing Webhook HMAC tokens are Base64 strings (~44 chars ending in "=")
 *   used to verify that requests actually originate from Teams.
 */

rule Teams_Incoming_Webhook_URL
{
    meta:
        description    = "Detects Microsoft Teams Incoming Webhook URLs"
        author         = "BERTON Jules - MORETTI Enzo"
        date           = "19-03-2026"
        version        = "1.0"
        reference      = "https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook"
        confidence     = "HIGH"
        false_positive = "LOW"
        severity       = "HIGH"
        tags           = "teams,microsoft,webhook,incoming"

    strings:
        // Classic incoming webhook URL on outlook.office.com
        $webhook_outlook  = /https:\/\/[a-zA-Z0-9\-]+\.webhook\.office\.com\/webhookb2\/[a-f0-9\-]{36}@[a-f0-9\-]{36}\/IncomingWebhook\/[a-f0-9]{32}\/[a-f0-9\-]{36}/

        // New-format webhook on webhook.office.com
        $webhook_office   = /https:\/\/[a-zA-Z0-9\-]+\.office\.com\/webhook\/[a-f0-9\-]{36}@[a-f0-9\-]{36}/

    condition:
        any of them
}


rule Teams_Power_Automate_Webhook_URL
{
    meta:
        description    = "Detects Microsoft Power Automate / Logic App webhook URLs used as Teams connectors"
        author         = "BERTON Jules - MORETTI Enzo"
        date           = "19-03-2026"
        version        = "1.0"
        reference      = "https://learn.microsoft.com/en-us/power-automate/"
        confidence     = "HIGH"
        false_positive = "LOW"
        severity       = "HIGH"
        tags           = "teams,power-automate,logic-app,webhook"

    strings:
        // Logic App / Power Automate URL with sig parameter (secret embedded in URL)
        $logic_url = /https:\/\/[a-zA-Z0-9\-]+\.logic\.azure\.com:443\/workflows\/[a-f0-9]{32}\/triggers\/manual\/paths\/invoke[^"'\s]{20,}&sig=[A-Za-z0-9%\-_]{20,}/

        // Power Platform direct automation URL
        $powerauto = /https:\/\/[a-zA-Z0-9\-]+\.environment\.api\.powerplatform\.com[^"'\s]{20,}&sig=[A-Za-z0-9%\-_]{20,}/

    condition:
        any of them
}


rule Teams_Outgoing_Webhook_HMAC_Token
{
    meta:
        description    = "Detects Microsoft Teams Outgoing Webhook HMAC security tokens"
        author         = "BERTON Jules - MORETTI Enzo"
        date           = "19-03-2026"
        version        = "1.0"
        reference      = "https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-outgoing-webhook"
        confidence     = "MEDIUM"
        false_positive = "MEDIUM"
        severity       = "HIGH"
        tags           = "teams,microsoft,hmac,security-token,outgoing-webhook"

    strings:
        // $var1 — teams_hmac_token / teams_security_token / teams_webhook_token
        $var1a = /teams[_.]hmac[_.]token[ \t]*[=:"']{1,3}[ \t]*['"]?[A-Za-z0-9+\/]{42,44}={0,2}['"]?/ nocase
        $var1b = /teams[_.]security[_.]token[ \t]*[=:"']{1,3}[ \t]*['"]?[A-Za-z0-9+\/]{42,44}={0,2}['"]?/ nocase
        $var1c = /teams[_.]webhook[_.]token[ \t]*[=:"']{1,3}[ \t]*['"]?[A-Za-z0-9+\/]{42,44}={0,2}['"]?/ nocase

        // $var2 — outgoing_webhook_secret
        $var2  = /outgoing[_.]webhook[_.]secret[ \t]*[=:"']{1,3}[ \t]*['"]?[A-Za-z0-9+\/]{42,44}={0,2}['"]?/ nocase

    condition:
        any of them
}


rule Teams_Graph_API_Bot_Secret
{
    meta:
        description    = "Detects Microsoft Teams Bot / Graph API application secrets in config files"
        author         = "BERTON Jules - MORETTI Enzo"
        date           = "19-03-2026"
        version        = "1.0"
        reference      = "https://learn.microsoft.com/en-us/microsoftteams/platform/bots/how-to/authentication/"
        confidence     = "MEDIUM"
        false_positive = "MEDIUM"
        severity       = "CRITICAL"
        tags           = "teams,graph-api,bot,client-secret,azure-ad"

    strings:
        // Bot Framework / Teams bot config file patterns
        $var1  = /MicrosoftAppPassword[ \t]*=[ \t]*['"]?[A-Za-z0-9.\-_~]{34,42}['"]?/

        // BOT_PASSWORD / BOT_SECRET / BOT_APP_PASSWORD / BOT_APP_SECRET
        $var2a = /BOT[_.]APP[_.]PASSWORD[ \t]*=[ \t]*['"]?[A-Za-z0-9.\-_~]{34,42}['"]?/ nocase
        $var2b = /BOT[_.]APP[_.]SECRET[ \t]*=[ \t]*['"]?[A-Za-z0-9.\-_~]{34,42}['"]?/ nocase
        $var2c = /BOT[_.]PASSWORD[ \t]*=[ \t]*['"]?[A-Za-z0-9.\-_~]{34,42}['"]?/ nocase
        $var2d = /BOT[_.]SECRET[ \t]*=[ \t]*['"]?[A-Za-z0-9.\-_~]{34,42}['"]?/ nocase

        // appsettings.json pattern (common in C# Teams bots)
        $json1 = /"MicrosoftAppPassword"[ \t]*:[ \t]*"[A-Za-z0-9.\-_~]{34,42}"/
        $json2 = /"MicrosoftAppId"[ \t]*:[ \t]*"[0-9a-f\-]{36}"/

    condition:
        ($var1 or any of ($var2*) or $json1) or ($json1 and $json2)
}


rule Teams_API_Secret_Service_Auth
{
    meta:
        description    = "Detects Teams Message Extension API Secret Service Auth credentials (apiSecretRegistrationId + API key)"
        author         = "BERTON Jules - MORETTI Enzo"
        date           = "19-03-2026"
        version        = "1.1"
        reference      = "https://learn.microsoft.com/en-us/microsoftteams/platform/messaging-extensions/api-based-secret-service-auth"
        confidence     = "HIGH"
        false_positive = "LOW"
        severity       = "HIGH"
        tags           = "teams,microsoft,message-extension,api-key,secret-service-auth"

    strings:
        // apiSecretRegistrationId in Teams app manifest (JSON)
        $reg_id_json   = /"apiSecretRegistrationId"[ \t]*:[ \t]*"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"/

        // apiSecretServiceAuthConfiguration block in manifest (structural anchor)
        $auth_config   = "\"authType\": \"apiSecretServiceAuth\""

        // Bearer token injection pattern in server-side code
        $bearer_key1   = /Authorization:[ \t]*Bearer[ \t]+[A-Za-z0-9\-_.~!@#$%^&*]{10,}/ nocase

        // TEAMS_API_SECRET / TEAMS_API_KEY — split to avoid (?:...) group
        $bearer_key2a  = /TEAMS[_.]API[_.]SECRET[ \t]*=[ \t]*['"]?[A-Za-z0-9\-_.~]{10,2048}['"]?/ nocase
        $bearer_key2b  = /TEAMS[_.]API[_.]KEY[ \t]*=[ \t]*['"]?[A-Za-z0-9\-_.~]{10,2048}['"]?/ nocase

        // Manifest composeExtensions block with apiBased type
        $compose_type  = "\"composeExtensionType\": \"apiBased\""

    condition:
        // High confidence: full manifest block present
        ($auth_config and $reg_id_json)
        or
        ($auth_config and $compose_type)
        or
        // Medium confidence: just the registration ID with surrounding context
        ($reg_id_json and $compose_type)
        or
        // Variable name anchor for the API key itself
        ($bearer_key1 or $bearer_key2a or $bearer_key2b)
}
