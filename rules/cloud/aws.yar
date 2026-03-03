/*
 * YARA Rules: Amazon Web Services (AWS) Credentials
 *
 * Author      : yara-apikey-rules contributors
 * Date        : 2025-03-03
 * Version     : 1.0
 * License     : MIT
 * Reference   : https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html
 *
 * Coverage:
 *   - AWS Access Key IDs  (AKIA, ASIA, ABIA, ACCA, AGPA, AIDA, AROA, AIPA, ANPA, ANVA)
 *   - AWS Secret Access Keys (context-aware)
 *   - AWS Session Tokens (temporary credentials)
 *   - AWS MWS (Marketplace Web Service) keys
 *
 * Notes on AWS Access Key prefixes:
 *   AKIA  = Long-term IAM user key
 *   ASIA  = Temporary (STS) key
 *   ABIA  = AWS STS service bearer token
 *   ACCA  = Context-specific credential
 *   AGPA  = Group policy attachment
 *   AIDA  = IAM user
 *   AROA  = Role
 *   AIPA  = EC2 instance profile
 *   ANPA  = Managed policy
 *   ANVA  = Version in a managed policy
 */

rule AWS_Access_Key_ID
{
    meta:
        description    = "Detects AWS Access Key IDs — all known IAM prefixes"
        author         = "yara-apikey-rules"
        date           = "2025-03-03"
        version        = "1.0"
        reference      = "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html"
        confidence     = "HIGH"
        false_positive = "LOW"
        severity       = "CRITICAL"
        tags           = "aws,cloud,iam,access-key"

    strings:
        // Long-term IAM user access key (most common leak)
        $akia   = /\bAKIA[A-Z0-9]{16}\b/

        // Temporary STS credentials
        $asia   = /\bASIA[A-Z0-9]{16}\b/

        // Other IAM entity prefixes (less common but valid)
        $others = /\b(ABIA|ACCA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16}\b/

    condition:
        any of them
}


rule AWS_Secret_Access_Key
{
    meta:
        description    = "Detects AWS Secret Access Keys based on known variable name patterns"
        author         = "yara-apikey-rules"
        date           = "2025-03-03"
        version        = "1.0"
        reference      = "https://docs.aws.amazon.com/general/latest/gr/aws-sec-cred-types.html"
        confidence     = "MEDIUM"
        false_positive = "MEDIUM"
        severity       = "CRITICAL"
        tags           = "aws,cloud,iam,secret-key"

    strings:
        // Variable name anchors — reduce false positives significantly
        $var1 = /aws[_\-\.]?secret[_\-\.]?(access[_\-\.]?)?key\s*[=:"']{1,3}\s*['"]?[A-Za-z0-9\/\+]{40}['"]?/  nocase
        $var2 = /secret[_\-\.]?access[_\-\.]?key\s*[=:"']{1,3}\s*['"]?[A-Za-z0-9\/\+]{40}['"]?/              nocase
        $var3 = /AWS_SECRET_ACCESS_KEY\s*=\s*['"]?[A-Za-z0-9\/\+]{40}['"]?/

        // JSON format (e.g. in ~/.aws/credentials or CloudFormation)
        $json = /"SecretAccessKey"\s*:\s*"[A-Za-z0-9\/\+]{40}"/

    condition:
        any of them
}


rule AWS_Session_Token
{
    meta:
        description    = "Detects AWS temporary session tokens (STS AssumeRole output)"
        author         = "yara-apikey-rules"
        date           = "2025-03-03"
        version        = "1.0"
        confidence     = "MEDIUM"
        false_positive = "MEDIUM"
        severity       = "HIGH"
        tags           = "aws,cloud,sts,session-token,temporary-credentials"

    strings:
        // JSON key pattern from STS API response
        $json_key     = /"SessionToken"\s*:\s*"[A-Za-z0-9\/\+=]{100,}"/

        // Environment variable pattern
        $env_var      = /AWS_SESSION_TOKEN\s*=\s*['"]?[A-Za-z0-9\/\+=]{100,}['"]?/

        // Variable name anchor
        $var          = /session[_\-\.]?token\s*[=:"']{1,3}\s*['"]?[A-Za-z0-9\/\+=]{100,}['"]?/  nocase

    condition:
        any of them
}


rule AWS_Credentials_File
{
    meta:
        description    = "Detects AWS credentials file structure (~/.aws/credentials)"
        author         = "yara-apikey-rules"
        date           = "2025-03-03"
        version        = "1.0"
        confidence     = "HIGH"
        false_positive = "LOW"
        severity       = "CRITICAL"
        tags           = "aws,cloud,credentials-file"

    strings:
        // Standard credentials file header
        $header       = "[default]"

        // Key fields present in credentials file
        $access_key   = /aws_access_key_id\s*=\s*[A-Z0-9]{20}/
        $secret_key   = /aws_secret_access_key\s*=\s*[A-Za-z0-9\/\+]{40}/

    condition:
        $header and ($access_key or $secret_key)
}


rule AWS_MWS_Key
{
    meta:
        description    = "Detects AWS Marketplace Web Service (MWS) authentication tokens"
        author         = "yara-apikey-rules"
        date           = "2025-03-03"
        version        = "1.0"
        confidence     = "HIGH"
        false_positive = "LOW"
        severity       = "HIGH"
        tags           = "aws,mws,marketplace"

    strings:
        $mws = /amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/

    condition:
        $mws
}
