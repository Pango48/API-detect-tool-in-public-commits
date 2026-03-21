/*
 * YARA Rules: Bitbucket Credentials
 *
 * Author      : BERTON Jules - MORETTI Enzo
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
 */

rule Bitbucket_App_Password
{
    meta:
        description    = "Detects Bitbucket App Passwords used for API authentication and git-over-HTTPS operations"
        author         = "BERTON Jules - MORETTI Enzo"
        date           = "2026-03-19"
        version        = "1.0"
        reference      = "https://support.atlassian.com/bitbucket-cloud/docs/app-passwords/"
        confidence     = "MEDIUM"
        false_positive = "MEDIUM"
        severity       = "HIGH"
        tags           = "bitbucket,app-password,token,atlassian"

    strings:
        // bitbucket_app_password / bitbucket_password (with app infix)
        $var1a   = /bitbucket[_\-.]app[_\-.]password[ \t]*[=:"']{1,3}[ \t]*['"]?[A-Za-z0-9]{20}['"]?/ nocase
        // bitbucket_password (without app infix)
        $var1b   = /bitbucket[_\-.]password[ \t]*[=:"']{1,3}[ \t]*['"]?[A-Za-z0-9]{20}['"]?/ nocase

        // BITBUCKET_APP_PASSWORD / BITBUCKET_APP_TOKEN
        $var2a   = /BITBUCKET[_.]APP[_.]PASSWORD[ \t]*=[ \t]*['"]?[A-Za-z0-9]{20}['"]?/ nocase
        $var2b   = /BITBUCKET[_.]APP[_.]TOKEN[ \t]*=[ \t]*['"]?[A-Za-z0-9]{20}['"]?/ nocase
        // BITBUCKET_PASSWORD / BITBUCKET_TOKEN (without APP infix)
        $var2c   = /BITBUCKET[_.]PASSWORD[ \t]*=[ \t]*['"]?[A-Za-z0-9]{20}['"]?/ nocase
        $var2d   = /BITBUCKET[_.]TOKEN[ \t]*=[ \t]*['"]?[A-Za-z0-9]{20}['"]?/ nocase

        // Git URL with embedded Bitbucket credentials
        $git_url = /https:\/\/[a-zA-Z0-9_\-\.]+:[A-Za-z0-9]{20}@bitbucket\.org/

        // .netrc file entry for Bitbucket
        $netrc   = /machine[ \t]+bitbucket\.org[ \t]+login[ \t]+\S+[ \t]+password[ \t]+[A-Za-z0-9]{20}/

    condition:
        any of them
}


rule Bitbucket_OAuth_Consumer_Secret
{
    meta:
        description    = "Detects Bitbucket OAuth 2.0 consumer key/secret pairs in config files or source code"
        author         = "BERTON Jules - MORETTI Enzo"
        date           = "2026-03-19"
        version        = "1.0"
        reference      = "https://support.atlassian.com/bitbucket-cloud/docs/use-oauth-on-bitbucket-cloud/"
        confidence     = "MEDIUM"
        false_positive = "MEDIUM"
        severity       = "HIGH"
        tags           = "bitbucket,oauth,consumer-secret,atlassian"

    strings:
        // bitbucket_oauth_consumer_secret (with consumer infix)
        $secret1a    = /bitbucket[_\-.]oauth[_\-.]consumer[_\-.]secret[ \t]*[=:"']{1,3}[ \t]*['"]?[A-Za-z0-9]{32,64}['"]?/ nocase
        // bitbucket_oauth_secret (without consumer infix)
        $secret1b    = /bitbucket[_\-.]oauth[_\-.]secret[ \t]*[=:"']{1,3}[ \t]*['"]?[A-Za-z0-9]{32,64}['"]?/ nocase

        // BITBUCKET_CLIENT_SECRET / BITBUCKET_CONSUMER_SECRET
        $secret2a    = /BITBUCKET[_.]CLIENT[_.]SECRET[ \t]*=[ \t]*['"]?[A-Za-z0-9]{32,64}['"]?/ nocase
        $secret2b    = /BITBUCKET[_.]CONSUMER[_.]SECRET[ \t]*=[ \t]*['"]?[A-Za-z0-9]{32,64}['"]?/ nocase

        // JSON config block with both key and secret
        $json_key_c  = /"client_key"[ \t]*:[ \t]*"[A-Za-z0-9]{18,22}"/
        $json_key_co = /"consumer_key"[ \t]*:[ \t]*"[A-Za-z0-9]{18,22}"/
        $json_sec_c  = /"client_secret"[ \t]*:[ \t]*"[A-Za-z0-9]{32,64}"/
        $json_sec_co = /"consumer_secret"[ \t]*:[ \t]*"[A-Za-z0-9]{32,64}"/

    condition:
        ($secret1a or $secret1b or $secret2a or $secret2b)
        or (($json_key_c or $json_key_co) and ($json_sec_c or $json_sec_co))
}


rule Bitbucket_Repository_Access_Token
{
    meta:
        description    = "Detects Bitbucket Repository Access Tokens (BRAT — ATBB prefix) scoped to a single repository"
        author         = "BERTON Jules - MORETTI Enzo"
        date           = "2026-03-19"
        version        = "1.0"
        reference      = "https://support.atlassian.com/bitbucket-cloud/docs/repository-access-tokens/"
        confidence     = "HIGH"
        false_positive = "LOW"
        severity       = "HIGH"
        tags           = "bitbucket,repository-access-token,brat,atlassian"

    strings:
        // BRAT: ATBB prefix + 32 alphanumeric chars
        $brat         = /ATBB[A-Za-z0-9]{32}/

        // BITBUCKET_REPO_ACCESS_TOKEN / BITBUCKET_ACCESS_TOKEN / BITBUCKET_TOKEN
        $atbb_var_a   = /BITBUCKET[_.]REPO[_.]ACCESS[_.]TOKEN[ \t]*[=:"']{1,3}[ \t]*['"]?ATBB[A-Za-z0-9]{32}['"]?/ nocase
        $atbb_var_b   = /BITBUCKET[_.]ACCESS[_.]TOKEN[ \t]*[=:"']{1,3}[ \t]*['"]?ATBB[A-Za-z0-9]{32}['"]?/ nocase
        $atbb_var_c   = /BITBUCKET[_.]TOKEN[ \t]*[=:"']{1,3}[ \t]*['"]?ATBB[A-Za-z0-9]{32}['"]?/ nocase
        // BB_ prefix variants
        $atbb_var_d   = /BB[_.]REPO[_.]ACCESS[_.]TOKEN[ \t]*[=:"']{1,3}[ \t]*['"]?ATBB[A-Za-z0-9]{32}['"]?/ nocase
        $atbb_var_e   = /BB[_.]ACCESS[_.]TOKEN[ \t]*[=:"']{1,3}[ \t]*['"]?ATBB[A-Za-z0-9]{32}['"]?/ nocase
        $atbb_var_f   = /BB[_.]TOKEN[ \t]*[=:"']{1,3}[ \t]*['"]?ATBB[A-Za-z0-9]{32}['"]?/ nocase

    condition:
        any of them
}


rule Bitbucket_Pipelines_Hardcoded_Secret
{
    meta:
        description    = "Detects hardcoded secrets in Bitbucket Pipelines YAML configuration (bitbucket-pipelines.yml)"
        author         = "BERTON Jules - MORETTI Enzo"
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

        // Hardcoded secret values — split by key name to avoid (?:...) alternation
        $env_password  = /PASSWORD[ \t]*:[ \t]*['"]?[A-Za-z0-9+\/]{20,}={0,2}['"]?/ nocase
        $env_secret    = /SECRET[ \t]*:[ \t]*['"]?[A-Za-z0-9+\/]{20,}={0,2}['"]?/ nocase
        $env_token     = /TOKEN[ \t]*:[ \t]*['"]?[A-Za-z0-9+\/]{20,}={0,2}['"]?/ nocase
        $env_api_key   = /API_KEY[ \t]*:[ \t]*['"]?[A-Za-z0-9+\/]{20,}={0,2}['"]?/ nocase
        $env_access    = /ACCESS_KEY[ \t]*:[ \t]*['"]?[A-Za-z0-9+\/]{20,}={0,2}['"]?/ nocase

        // Bitbucket-specific built-in variable leak (should never be hardcoded)
        $bb_token      = /BITBUCKET_REPO_FULL_NAME[ \t]*[=:][ \t]*['"]?[A-Za-z0-9\/\-_.]{5,}['"]?/

    condition:
        $pipelines_marker and
        ($env_password or $env_secret or $env_token or $env_api_key or $env_access or $bb_token)
}
