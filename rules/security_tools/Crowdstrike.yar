/*
 * YARA Rules: CrowdStrike Falcon API Credentials
 *
 * Author      : BERTON Jules - MORETTI Enzo
 * Date        : 19-03-2026
 * Version     : 1.0
 * Reference   : https://www.crowdstrike.com/blog/tech-center/get-access-falcon-apis/
 *               https://www.tines.com/blog/getting-connected-to-the-crowdstrike-api/
 *
 * Coverage:
 *   - CrowdStrike Falcon OAuth2 Client ID (32-char lowercase hex)
 *   - CrowdStrike Falcon OAuth2 Client Secret (40-char alphanumeric)
 *   - Falcon Customer ID (CID) — 32-char hex + optional checksum suffix
 *   - Falcon Data Replicator (FDR) credentials
 *
 * Key formats (from official CrowdStrike and Tines documentation):
 *   Client ID     : 32-character lowercase hexadecimal string
 *   Client Secret : 40-character mixed-case alphanumeric string
 *   CID           : 32-character uppercase hex, optionally followed by -XX checksum
 *                   Example: 3061C7FF3B634E22B38274D4B586558E-20
 *
 * Note: CrowdStrike deprecated key-based authentication in favor of OAuth2.
 * All modern integrations use Client ID + Client Secret to obtain a Bearer token.
 * OAuth2 access tokens have a 30-minute validity period.
 *
 * Threat context:
 *   CrowdStrike credentials are extremely high value:
 *   - Full EDR telemetry access (process trees, network connections, file events)
 *   - Ability to deploy/modify detection policies and exclusions
 *   - Remote script execution on managed endpoints (Real Time Response)
 *   - Access to Falcon Intelligence threat reports
 *   - Lateral movement via Falcon Identity Protection data
 */

rule CrowdStrike_OAuth2_Client_Credentials
{
    meta:
        description    = "Detects CrowdStrike Falcon OAuth2 Client ID and Secret in config or env files"
        author         = "BERTON Jules - MORETTI Enzo"
        date           = "19-03-2026"
        version        = "1.0"
        reference      = "https://www.tines.com/blog/getting-connected-to-the-crowdstrike-api/"
        confidence     = "HIGH"
        false_positive = "LOW"
        severity       = "CRITICAL"
        tags           = "crowdstrike,falcon,oauth2,client-id,client-secret,edr"

    strings:
        // Client ID — 32-char lowercase hex (documented by CrowdStrike and Tines)
        $client_id1   = /FALCON[_\.]?CLIENT[_\.]?ID\s*=\s*['"]?[0-9a-f]{32}['"]?/  nocase
        $client_id2   = /CROWDSTRIKE[_\.]?CLIENT[_\.]?ID\s*=\s*['"]?[0-9a-f]{32}['"]?/  nocase
        $client_id3   = /"client[_\-]?id"\s*:\s*"[0-9a-f]{32}"/

        // Client Secret — 40-char mixed alphanumeric (documented by CrowdStrike and Tines)
        $client_sec1  = /FALCON[_\.]?CLIENT[_\.]?SECRET\s*=\s*['"]?[A-Za-z0-9]{40}['"]?/  nocase
        $client_sec2  = /CROWDSTRIKE[_\.]?(?:CLIENT[_\.]?)?SECRET\s*=\s*['"]?[A-Za-z0-9]{40}['"]?/  nocase
        $client_sec3  = /"client[_\-]?secret"\s*:\s*"[A-Za-z0-9]{40}"/

    condition:
        // High confidence: both present (typical .env or config file leak)
        (any of ($client_id*) and any of ($client_sec*))
        or
        // Named anchor alone — Falcon/CrowdStrike prefix makes it specific enough
        $client_id1 or $client_id2 or $client_sec1 or $client_sec2
}


rule CrowdStrike_Customer_ID
{
    meta:
        description    = "Detects CrowdStrike Falcon Customer ID (CID) — used to identify the tenant"
        author         = "BERTON Jules - MORETTI Enzo"
        date           = "19-03-2026"
        version        = "1.0"
        reference      = "https://docs.redcanary.com/docs/create-api-credentials-to-integrate-your-existing-crowdstrike-falcon-environment-with-red-canary"
        confidence     = "MEDIUM"
        false_positive = "MEDIUM"
        severity       = "MEDIUM"
        tags           = "crowdstrike,falcon,cid,customer-id,tenant"

    strings:
        // CID — 32-char uppercase hex, optionally followed by -XX checksum suffix
        $cid_env      = /(?:FALCON|CROWDSTRIKE)[_\.]?CID\s*=\s*['"]?[0-9A-F]{32}(?:-[0-9A-F]{2})?['"]?/  nocase
        $cid_json     = /"(?:falcon[_\-]?)?cid"\s*:\s*"[0-9A-Fa-f]{32}(?:-[0-9A-Fa-f]{2})?"/
        $cid_comment  = /Falcon\s+CID\s*[=:]\s*[0-9A-F]{32}/  nocase

    condition:
        any of them
}


rule CrowdStrike_Falcon_Base_URL
{
    meta:
        description    = "Detects CrowdStrike Falcon API base URLs with credential context — indicates active integration config"
        author         = "BERTON Jules - MORETTI Enzo"
        date           = "19-03-2026"
        version        = "1.0"
        confidence     = "MEDIUM"
        false_positive = "LOW"
        severity       = "HIGH"
        tags           = "crowdstrike,falcon,api-url,config"

    strings:
        // CrowdStrike regional API base URLs
        $url_us1    = "api.crowdstrike.com"
        $url_us2    = "api.us-2.crowdstrike.com"
        $url_eu1    = "api.eu-1.crowdstrike.com"
        $url_gov    = "api.laggar.gcw.crowdstrike.com"

        // Credential fields in proximity
        $secret     = /client[_\-]?secret\s*[=:"']{1,3}\s*['"]?[A-Za-z0-9]{40}['"]?/  nocase
        $client_id  = /client[_\-]?id\s*[=:"']{1,3}\s*['"]?[0-9a-f]{32}['"]?/  nocase

    condition:
        any of ($url_*) and ($secret or $client_id)
}


rule CrowdStrike_FDR_Credentials
{
    meta:
        description    = "Detects CrowdStrike Falcon Data Replicator (FDR) credentials — grants access to full telemetry stream"
        author         = "BERTON Jules - MORETTI Enzo"
        date           = "19-03-2026"
        version        = "1.0"
        reference      = "https://docs.redcanary.com/docs/create-api-credentials-to-integrate-your-existing-crowdstrike-falcon-environment-with-red-canary"
        confidence     = "HIGH"
        false_positive = "LOW"
        severity       = "CRITICAL"
        tags           = "crowdstrike,falcon,fdr,data-replicator,telemetry"

    strings:
        // FDR-specific credential variable names
        $fdr_id     = /(?:FALCON[_\.]?)?FDR[_\.]?CLIENT[_\.]?ID\s*=\s*['"]?[0-9a-f]{32}['"]?/  nocase
        $fdr_secret = /(?:FALCON[_\.]?)?FDR[_\.]?(?:CLIENT[_\.]?)?SECRET\s*=\s*['"]?[A-Za-z0-9]{40}['"]?/  nocase
        $fdr_sqs    = /FDR[_\.]?(?:SQS[_\.]?)?(?:NOTIFICATION[_\.]?)?URL\s*=\s*['"]?https:\/\/sqs\./  nocase

        // FDR doc pattern — appears in integration setup docs
        $fdr_label  = "Falcon Data Replicator"

    condition:
        any of ($fdr_id, $fdr_secret, $fdr_sqs)
        or
        ($fdr_label and any of ($fdr_id, $fdr_secret))
}
