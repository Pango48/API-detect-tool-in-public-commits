/*
 * YARA Rules: Bitbucket Credentials
 *
 * Date        : 19-03-2026
 * Version     : 1.0
 * Reference   : https://support.atlassian.com/bitbucket-cloud/docs/app-passwords/
 *               https://support.atlassian.com/bitbucket-cloud/docs/use-oauth-on-bitbucket-cloud/
 *               https://support.atlassian.com/bitbucket-cloud/docs/repository-access-tokens/
 *
 * Coverage:
 *   - Bitbucket App Passwords (API + git authentication)
 *   - Bitbucket OAuth 2.0 Consumer key/secret pairs
 *   - Bitbucket Repository Access Tokens (BRAT — ATBB prefix)
 *   - Bitbucket Pipelines environment variables (hardcoded secrets)
 *
 * Architecture notes:
 *   Bitbucket App Passwords are the primary authentication mechanism for REST API
 *   calls and git-over-HTTPS operations. They do not follow a strict prefix convention,
 *   making detection anchor-based (config key names + value patterns).
 *   Repository Access Tokens (BRAT, introduced 2022) use the Atlassian ATBB prefix
 *   and are scoped to a single repository — leaking them grants full read/write on
 *   that repo. OAuth consumer secrets allow impersonating the registered app.
 */

rule Bitbucket_App_Password
{
    meta:
        description    = "Detects Bitbucket App Passwords used for API authentication and git-over-HTTPS operations"
        author         = "yara-apikey-rules"
        date           = "2026-03-19"
        version        = "1.0"
        reference      = "https://support.atlassian.com/bitbucket-cloud/docs/app-passwords/"
        confidence     = "MEDIUM"
        false_positive = "MEDIUM"
        severity       = "HIGH"
        tags           = "bitbucket,app-password,token,atlassian"

    strings:
        // Config key anchor + 20-char base62 value
        $var1 = /bitbucket[_\-\.]?(?:app[_\-\.]?)?password\s*[=:"']{1,3}\s*['"]?[A-Za-z0-9]{20}['"]?/  nocase
        $var2 = /BITBUCKET[_\.]?(?:APP[_\.]?)?(?:PASSWORD|TOKEN)\s*=\s*['"]?[A-Za-z0-9]{20}['"]?/  nocase

        // Git URL with embedded Bitbucket credentials
        $git_url = /https:\/\/[a-zA-Z0-9_\-\.]+:[A-Za-z0-9]{20}@bitbucket\.org/

        // .netrc file entry for Bitbucket
        $netrc = /machine\s+bitbucket\.org\s+login\s+\S+\s+password\s+[A-Za-z0-9]{20}/

    condition:
        any of them
}


rule Bitbucket_OAuth_Consumer_Secret
{
    meta:
        description    = "Detects Bitbucket OAuth 2.0 consumer key/secret pairs in config files or source code"
        author         = "yara-apikey-rules"
        date           = "2026-03-19"
        version        = "1.0"
        reference      = "https://support.atlassian.com/bitbucket-cloud/docs/use-oauth-on-bitbucket-cloud/"
        confidence     = "MEDIUM"
        false_positive = "MEDIUM"
        severity       = "HIGH"
        tags           = "bitbucket,oauth,consumer-secret,atlassian"

    strings:
        // OAuth consumer secret anchor in env var or config
        $secret1 = /bitbucket[_\-\.]?oauth[_\-\.]?(?:consumer[_\-\.]?)?secret\s*[=:"']{1,3}\s*['"]?[A-Za-z0-9]{32,64}['"]?/  nocase
        $secret2 = /BITBUCKET[_\.]?(?:CLIENT|CONSUMER)[_\.]?SECRET\s*=\s*['"]?[A-Za-z0-9]{32,64}['"]?/  nocase

        // JSON config block with both key and secret
        $json_key    = /"(?:client|consumer)_key"\s*:\s*"[A-Za-z0-9]{18,22}"/
        $json_secret = /"(?:client|consumer)_secret"\s*:\s*"[A-Za-z0-9]{32,64}"/

    condition:
        ($secret1 or $secret2) or ($json_key and $json_secret)
}


rule Bitbucket_Repository_Access_Token
{
    meta:
        description    = "Detects Bitbucket Repository Access Tokens (BRAT — ATBB prefix) scoped to a single repository"
        author         = "yara-apikey-rules"
        date           = "2026-03-19"
        version        = "1.0"
        reference      = "https://support.atlassian.com/bitbucket-cloud/docs/repository-access-tokens/"
        confidence     = "HIGH"
        false_positive = "LOW"
        severity       = "HIGH"
        tags           = "bitbucket,repository-access-token,brat,atlassian"

    strings:
        // BRAT: ATBB prefix + 32 alphanumeric chars (Atlassian token format)
        $brat = /ATBB[A-Za-z0-9]{32}/

        // Named variable context containing ATBB token
        $atbb_var = /(?:BITBUCKET|BB)[_\.]?(?:REPO[_\.]?)?(?:ACCESS[_\.]?)?TOKEN\s*[=:"']{1,3}\s*['"]?ATBB[A-Za-z0-9]{32}['"]?/  nocase

    condition:
        any of them
}


rule Bitbucket_Pipelines_Hardcoded_Secret
{
    meta:
        description    = "Detects hardcoded secrets in Bitbucket Pipelines YAML configuration (bitbucket-pipelines.yml)"
        author         = "yara-apikey-rules"
        date           = "2026-03-19"
        version        = "1.0"
        reference      = "https://support.atlassian.com/bitbucket-cloud/docs/variables-and-secrets/"
        confidence     = "MEDIUM"
        false_positive = "MEDIUM"
        severity       = "HIGH"
        tags           = "bitbucket,pipelines,ci-cd,hardcoded-secret"

    strings:
        // Pipelines YAML file marker
        $pipelines_marker = "bitbucket-pipelines.yml"

        // Hardcoded secret value in a step environment block (not $BITBUCKET_* built-in)
        $env_secret = /(?:PASSWORD|SECRET|TOKEN|API_KEY|ACCESS_KEY)\s*:\s*['"]?[A-Za-z0-9\+\/]{20,}={0,2}['"]?/  nocase

        // Bitbucket-specific built-in variable leak (should never be hardcoded)
        $bb_token = /BITBUCKET_REPO_FULL_NAME\s*[=:]\s*['"]?[A-Za-z0-9\/\-_\.]{5,}['"]?/

    condition:
        $pipelines_marker and ($env_secret or $bb_token)
}
