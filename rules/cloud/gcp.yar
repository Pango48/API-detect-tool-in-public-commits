/*
 * YARA Rules: Google Cloud Platform (GCP) Credentials
 *
 * Author      : yara-apikey-rules contributors
 * Date        : 2025-03-03
 * Version     : 1.0
 * License     : MIT
 * Reference   : https://cloud.google.com/iam/docs/service-account-creds
 *
 * Coverage:
 *   - GCP Service Account JSON key files
 *   - Google API keys (AIza prefix)
 *   - Google OAuth2 tokens (client secrets, refresh tokens)
 *   - Firebase API keys
 *   - Application Default Credentials (ADC)
 *
 * Important notes:
 *   - GCP Service Account keys are JSON files containing a private RSA key.
 *     The most reliable anchor is the "type": "service_account" field combined
 *     with the presence of "private_key" or "client_email".
 *   - Google API keys (AIza...) are 39 chars and shared across Google APIs,
 *     Maps, Firebase, Gemini, etc. They are high-value targets.
 */

rule GCP_Service_Account_Key
{
    meta:
        description    = "Detects GCP Service Account JSON key files"
        author         = "yara-apikey-rules"
        date           = "2025-03-03"
        version        = "1.0"
        reference      = "https://cloud.google.com/iam/docs/keys-create-delete"
        confidence     = "HIGH"
        false_positive = "LOW"
        severity       = "CRITICAL"
        tags           = "gcp,cloud,service-account,credential-file"

    strings:
        // Mandatory discriminator field
        $type         = "\"type\": \"service_account\""

        // Private key block (RSA key embedded in JSON)
        $private_key  = "-----BEGIN RSA PRIVATE KEY-----"
        $private_key2 = "-----BEGIN PRIVATE KEY-----"

        // Client email follows a known pattern: name@project.iam.gserviceaccount.com
        $client_email = /[a-z0-9\-]+@[a-z0-9\-]+\.iam\.gserviceaccount\.com/

        // Auth URI anchor
        $auth_uri     = "https://accounts.google.com/o/oauth2/auth"

    condition:
        $type and (1 of ($private_key*) or $client_email or $auth_uri)
}


rule GCP_API_Key
{
    meta:
        description    = "Detects Google/GCP/Firebase/Gemini API keys (AIza prefix, 39 chars)"
        author         = "yara-apikey-rules"
        date           = "2025-03-03"
        version        = "1.0"
        reference      = "https://cloud.google.com/docs/authentication/api-keys"
        confidence     = "HIGH"
        false_positive = "LOW"
        severity       = "HIGH"
        tags           = "gcp,google,firebase,gemini,api-key"

    strings:
        // Standard Google API key — used for Maps, YouTube, Gemini, etc.
        $api_key = /AIza[0-9A-Za-z\-_]{35}/

    condition:
        $api_key
}


rule GCP_OAuth2_Client_Secret
{
    meta:
        description    = "Detects GCP OAuth2 client secret file (client_secrets.json)"
        author         = "yara-apikey-rules"
        date           = "2025-03-03"
        version        = "1.0"
        reference      = "https://developers.google.com/identity/protocols/oauth2"
        confidence     = "HIGH"
        false_positive = "LOW"
        severity       = "HIGH"
        tags           = "gcp,google,oauth2,client-secret"

    strings:
        // OAuth2 client types in Google's JSON format
        $installed    = "\"installed\":"
        $web          = "\"web\":"

        // Required fields in client_secrets.json
        $client_id    = /[0-9]+-[a-z0-9]+\.apps\.googleusercontent\.com/
        $client_sec   = /"client_secret"\s*:\s*"GOCSPX-[A-Za-z0-9\-_]{28}"/

        // Older client secret format (pre-2021)
        $client_sec2  = /"client_secret"\s*:\s*"[A-Za-z0-9\-_]{24}"/

    condition:
        ($installed or $web) and ($client_id or $client_sec or $client_sec2)
}


rule GCP_OAuth2_Refresh_Token
{
    meta:
        description    = "Detects GCP OAuth2 refresh tokens in config or credential files"
        author         = "yara-apikey-rules"
        date           = "2025-03-03"
        version        = "1.0"
        confidence     = "MEDIUM"
        false_positive = "MEDIUM"
        severity       = "HIGH"
        tags           = "gcp,google,oauth2,refresh-token"

    strings:
        // Refresh token field anchors
        $field1 = /"refresh_token"\s*:\s*"1\/\/[A-Za-z0-9\-_]{40,}"/
        $field2 = /refresh_token\s*=\s*1\/\/[A-Za-z0-9\-_]{40,}/

    condition:
        any of them
}


rule GCP_Application_Default_Credentials
{
    meta:
        description    = "Detects GCP Application Default Credentials (ADC) JSON file structure"
        author         = "yara-apikey-rules"
        date           = "2025-03-03"
        version        = "1.0"
        reference      = "https://cloud.google.com/docs/authentication/application-default-credentials"
        confidence     = "HIGH"
        false_positive = "LOW"
        severity       = "CRITICAL"
        tags           = "gcp,google,adc,application-default-credentials"

    strings:
        // ADC file can be service_account OR authorized_user type
        $type_sa   = "\"type\": \"service_account\""
        $type_user = "\"type\": \"authorized_user\""

        // Token URI present in both types
        $token_uri = "https://oauth2.googleapis.com/token"

    condition:
        ($type_sa or $type_user) and $token_uri
}
