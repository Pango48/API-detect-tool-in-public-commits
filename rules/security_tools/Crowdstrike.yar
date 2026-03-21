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
        // Client ID anchors
        $client_id1   = /FALCON[_.]CLIENT[_.]ID[ \t]*=[ \t]*['"]?[0-9a-f]{32}['"]?/ nocase
        $client_id2   = /CROWDSTRIKE[_.]CLIENT[_.]ID[ \t]*=[ \t]*['"]?[0-9a-f]{32}['"]?/ nocase
        $client_id3   = /"client[_\-]?id"[ \t]*:[ \t]*"[0-9a-f]{32}"/

        // Client Secret anchors
        $client_sec1  = /FALCON[_.]CLIENT[_.]SECRET[ \t]*=[ \t]*['"]?[A-Za-z0-9]{40}['"]?/ nocase
        // CROWDSTRIKE_CLIENT_SECRET — with CLIENT infix
        $client_sec2a = /CROWDSTRIKE[_.]CLIENT[_.]SECRET[ \t]*=[ \t]*['"]?[A-Za-z0-9]{40}['"]?/ nocase
        // CROWDSTRIKE_SECRET — without CLIENT infix
        $client_sec2b = /CROWDSTRIKE[_.]SECRET[ \t]*=[ \t]*['"]?[A-Za-z0-9]{40}['"]?/ nocase
        $client_sec3  = /"client[_\-]?secret"[ \t]*:[ \t]*"[A-Za-z0-9]{40}"/

    condition:
        (any of ($client_id*) and any of ($client_sec*))
        or
        $client_id1 or $client_id2 or $client_sec1 or $client_sec2a or $client_sec2b
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
        // FALCON_CID — with FALCON prefix
        $cid_env_f    = /FALCON[_.]CID[ \t]*=[ \t]*['"]?[0-9A-F]{32}['"]?/ nocase
        // CROWDSTRIKE_CID — with CROWDSTRIKE prefix
        $cid_env_cs   = /CROWDSTRIKE[_.]CID[ \t]*=[ \t]*['"]?[0-9A-F]{32}['"]?/ nocase
        // CID with checksum suffix — FALCON_CID=XXXX-YY
        $cid_env_f2   = /FALCON[_.]CID[ \t]*=[ \t]*['"]?[0-9A-F]{32}-[0-9A-F]{2}['"]?/ nocase
        $cid_env_cs2  = /CROWDSTRIKE[_.]CID[ \t]*=[ \t]*['"]?[0-9A-F]{32}-[0-9A-F]{2}['"]?/ nocase

        // JSON — falcon_cid key
        $cid_json_f   = /"falcon[_\-]?cid"[ \t]*:[ \t]*"[0-9A-Fa-f]{32}"/
        // JSON — cid key (generic)
        $cid_json     = /"cid"[ \t]*:[ \t]*"[0-9A-Fa-f]{32}"/

        $cid_comment  = /Falcon[ \t]+CID[ \t]*[=:][ \t]*[0-9A-F]{32}/ nocase

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
        $url_us1    = "api.crowdstrike.com"
        $url_us2    = "api.us-2.crowdstrike.com"
        $url_eu1    = "api.eu-1.crowdstrike.com"
        $url_gov    = "api.laggar.gcw.crowdstrike.com"

        $secret     = /client[_\-]?secret[ \t]*[=:"']{1,3}[ \t]*['"]?[A-Za-z0-9]{40}['"]?/ nocase
        $client_id  = /client[_\-]?id[ \t]*[=:"']{1,3}[ \t]*['"]?[0-9a-f]{32}['"]?/ nocase

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
        // FDR Client ID — with FALCON prefix
        $fdr_id_f     = /FALCON[_.]FDR[_.]CLIENT[_.]ID[ \t]*=[ \t]*['"]?[0-9a-f]{32}['"]?/ nocase
        // FDR Client ID — without FALCON prefix
        $fdr_id       = /FDR[_.]CLIENT[_.]ID[ \t]*=[ \t]*['"]?[0-9a-f]{32}['"]?/ nocase

        // FDR Secret — with FALCON prefix, with CLIENT infix
        $fdr_sec_f_c  = /FALCON[_.]FDR[_.]CLIENT[_.]SECRET[ \t]*=[ \t]*['"]?[A-Za-z0-9]{40}['"]?/ nocase
        // FDR Secret — with FALCON prefix, without CLIENT infix
        $fdr_sec_f    = /FALCON[_.]FDR[_.]SECRET[ \t]*=[ \t]*['"]?[A-Za-z0-9]{40}['"]?/ nocase
        // FDR Secret — without FALCON prefix, with CLIENT infix
        $fdr_sec_c    = /FDR[_.]CLIENT[_.]SECRET[ \t]*=[ \t]*['"]?[A-Za-z0-9]{40}['"]?/ nocase
        // FDR Secret — without FALCON prefix, without CLIENT infix
        $fdr_sec      = /FDR[_.]SECRET[ \t]*=[ \t]*['"]?[A-Za-z0-9]{40}['"]?/ nocase

        // FDR SQS URL — with FALCON prefix, with SQS+NOTIFICATION infixes
        $fdr_sqs_f_sn = /FALCON[_.]FDR[_.]SQS[_.]NOTIFICATION[_.]URL[ \t]*=[ \t]*['"]?https:\/\/sqs\./ nocase
        // FDR SQS URL — with FALCON prefix, with SQS infix only
        $fdr_sqs_f_s  = /FALCON[_.]FDR[_.]SQS[_.]URL[ \t]*=[ \t]*['"]?https:\/\/sqs\./ nocase
        // FDR SQS URL — with FALCON prefix, no infixes
        $fdr_sqs_f    = /FALCON[_.]FDR[_.]URL[ \t]*=[ \t]*['"]?https:\/\/sqs\./ nocase
        // FDR SQS URL — without FALCON prefix, with SQS+NOTIFICATION infixes
        $fdr_sqs_sn   = /FDR[_.]SQS[_.]NOTIFICATION[_.]URL[ \t]*=[ \t]*['"]?https:\/\/sqs\./ nocase
        // FDR SQS URL — without FALCON prefix, with SQS infix only
        $fdr_sqs_s    = /FDR[_.]SQS[_.]URL[ \t]*=[ \t]*['"]?https:\/\/sqs\./ nocase
        // FDR SQS URL — without FALCON prefix, no infixes
        $fdr_sqs      = /FDR[_.]URL[ \t]*=[ \t]*['"]?https:\/\/sqs\./ nocase

        $fdr_label    = "Falcon Data Replicator"

    condition:
        any of ($fdr_id*, $fdr_sec*, $fdr_sqs*)
        or
        ($fdr_label and (any of ($fdr_id*) or any of ($fdr_sec*)))
}
