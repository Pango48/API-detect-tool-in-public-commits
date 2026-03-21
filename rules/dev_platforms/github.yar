/*
 * YARA Rules: GitHub Credentials
 *
 * Author      : BERTON Jules - MORETTI Enzo
 * Date        : 19-03-2026
 * Version     : 1.0
 * Reference   : https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-authentication-to-github
 *
 * Coverage:
 *   - GitHub Personal Access Tokens (classic & fine-grained)
 *   - GitHub OAuth App tokens & GitHub App installation tokens
 *   - GitHub App private keys (RSA PEM)
 *   - GitHub Actions hardcoded secrets in workflow YAML files
 *
 * Architecture notes:
 *   GitHub introduced prefixed token formats in 2021 (ghp_, gho_, ghu_, ghs_, ghr_)
 *   and fine-grained tokens in 2022 (github_pat_). Classic tokens are 40-char hex strings.
 *   Leaking any of these grants read/write access to source code repositories and, in many
 *   cases, full account takeover or CI/CD pipeline hijacking.
 *   GitHub App private keys (RSA PEM) allow generating short-lived installation tokens
 *   with arbitrary repository scopes — leaking them is equivalent to persistent backdoor access.
 */

rule GitHub_Personal_Access_Token_Classic
{
    meta:
        description    = "Detects GitHub classic Personal Access Tokens (40-char hex)"
        author         = "BERTON Jules - MORETTI Enzo"
        date           = "2026-03-19"
        version        = "1.0"
        reference      = "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens"
        confidence     = "MEDIUM"
        false_positive = "MEDIUM"
        severity       = "CRITICAL"
        tags           = "github,token,pat,personal-access-token"

    strings:
        // Classic PAT anchor — github/gh + token
        $var1a = /github[_\-.]token[ \t]*[=:"']{1,3}[ \t]*['"]?[0-9a-f]{40}['"]?/ nocase
        // github/gh + pat
        $var1b = /github[_\-.]pat[ \t]*[=:"']{1,3}[ \t]*['"]?[0-9a-f]{40}['"]?/ nocase
        // github/gh + access_token
        $var1c = /github[_\-.]access[_\-.]token[ \t]*[=:"']{1,3}[ \t]*['"]?[0-9a-f]{40}['"]?/ nocase
        // github/gh + personal_access_token
        $var1d = /github[_\-.]personal[_\-.]access[_\-.]token[ \t]*[=:"']{1,3}[ \t]*['"]?[0-9a-f]{40}['"]?/ nocase
        // gh_ prefix variants
        $var1e = /gh[_\-.]token[ \t]*[=:"']{1,3}[ \t]*['"]?[0-9a-f]{40}['"]?/ nocase
        $var1f = /gh[_\-.]pat[ \t]*[=:"']{1,3}[ \t]*['"]?[0-9a-f]{40}['"]?/ nocase

        // Canonical env var
        $var2  = /GITHUB[_.]TOKEN[ \t]*=[ \t]*['"]?[0-9a-f]{40}['"]?/ nocase

        // Git credential helper storage
        $git_url = /https:\/\/[a-zA-Z0-9_\-\.]+:[0-9a-f]{40}@github\.com/

    condition:
        any of them
}


rule GitHub_Personal_Access_Token_Fine_Grained
{
    meta:
        description    = "Detects GitHub fine-grained Personal Access Tokens (github_pat_ prefix)"
        author         = "BERTON Jules - MORETTI Enzo"
        date           = "2026-03-19"
        version        = "1.0"
        reference      = "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens#fine-grained-personal-access-tokens"
        confidence     = "HIGH"
        false_positive = "LOW"
        severity       = "CRITICAL"
        tags           = "github,token,pat,fine-grained,personal-access-token"

    strings:
        // Fine-grained PAT: github_pat_ + 82 base62 chars
        $fine_grained = /github_pat_[A-Za-z0-9_]{82}/

    condition:
        $fine_grained
}


rule GitHub_OAuth_And_App_Tokens
{
    meta:
        description    = "Detects GitHub OAuth app tokens, user-to-server tokens, server-to-server tokens and refresh tokens"
        author         = "BERTON Jules - MORETTI Enzo"
        date           = "2026-03-19"
        version        = "1.0"
        reference      = "https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/about-authentication-with-a-github-app"
        confidence     = "HIGH"
        false_positive = "LOW"
        severity       = "CRITICAL"
        tags           = "github,oauth,app-token,installation-token"

    strings:
        // ghp_ = Personal Access Token (new format)
        $ghp = /ghp_[A-Za-z0-9]{36}/

        // gho_ = OAuth access token
        $gho = /gho_[A-Za-z0-9]{36}/

        // ghu_ = GitHub App user-to-server token
        $ghu = /ghu_[A-Za-z0-9]{36}/

        // ghs_ = GitHub App server-to-server (installation) token
        $ghs = /ghs_[A-Za-z0-9]{36}/

        // ghr_ = GitHub App refresh token
        $ghr = /ghr_[A-Za-z0-9]{76}/

    condition:
        any of them
}


rule GitHub_App_Private_Key
{
    meta:
        description    = "Detects GitHub App RSA private keys used to generate installation tokens"
        author         = "BERTON Jules - MORETTI Enzo"
        date           = "2026-03-19"
        version        = "1.0"
        reference      = "https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/managing-private-keys-for-github-apps"
        confidence     = "HIGH"
        false_positive = "LOW"
        severity       = "CRITICAL"
        tags           = "github,app,private-key,rsa"

    strings:
        // PEM header combined with GitHub App context keywords
        $pem_header = "-----BEGIN RSA PRIVATE KEY-----"
        $ctx1       = "github-app"  nocase
        $ctx2       = "GITHUB_APP"
        $ctx3       = "githubApp"

    condition:
        $pem_header and any of ($ctx*)
}


rule GitHub_Actions_Secret_In_Workflow
{
    meta:
        description    = "Detects hardcoded secrets inside GitHub Actions workflow YAML files (should use secrets context)"
        author         = "BERTON Jules - MORETTI Enzo"
        date           = "2026-03-19"
        version        = "1.0"
        reference      = "https://docs.github.com/en/actions/security-guides/encrypted-secrets"
        confidence     = "MEDIUM"
        false_positive = "MEDIUM"
        severity       = "HIGH"
        tags           = "github,actions,workflow,secret,ci-cd"

    strings:
        // Hardcoded GITHUB_TOKEN value (not referencing secrets context)
        $env_tok_github = /GITHUB_TOKEN[ \t]*:[ \t]*['"]?[A-Za-z0-9_\-\.]{20,}['"]?/
        // Hardcoded GH_TOKEN value
        $env_tok_gh     = /GH_TOKEN[ \t]*:[ \t]*['"]?[A-Za-z0-9_\-\.]{20,}['"]?/
        // Hardcoded GITHUB_PAT value
        $env_tok_pat    = /GITHUB_PAT[ \t]*:[ \t]*['"]?[A-Za-z0-9_\-\.]{20,}['"]?/

        // Generic hardcoded secret fields — split by key name
        $env_api_key    = /API_KEY[ \t]*:[ \t]*['"]?[A-Za-z0-9+\/]{20,}={0,2}['"]?/ nocase
        $env_secret     = /SECRET[ \t]*:[ \t]*['"]?[A-Za-z0-9+\/]{20,}={0,2}['"]?/ nocase
        $env_password   = /PASSWORD[ \t]*:[ \t]*['"]?[A-Za-z0-9+\/]{20,}={0,2}['"]?/ nocase
        $env_token      = /TOKEN[ \t]*:[ \t]*['"]?[A-Za-z0-9+\/]{20,}={0,2}['"]?/ nocase

    condition:
        any of them
}
