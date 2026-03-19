/*
 * YARA Rules: GitLab Credentials
 *
 * Author      : BERTON Jules - MORETTI Enzo
 * Date        : 19-03-2026
 * Version     : 1.0
 * Reference   : https://docs.gitlab.com/ee/security/tokens/
 *
 * Coverage:
 *   - GitLab Personal Access Tokens (glpat- prefix & legacy)
 *   - GitLab Deploy Tokens (gldt-)
 *   - GitLab CI/CD Bridge tokens (glcbt-)
 *   - GitLab Service Account tokens (glsoat-)
 *   - GitLab Agent tokens (glagent-)
 *   - GitLab Runner registration tokens (glrt-)
 *
 * Architecture notes:
 *   GitLab introduced token prefixes in v14.5 (glpat-) and extended them across
 *   all token types through v15.x. Pre-prefix tokens (20 alphanumeric chars) are
 *   still valid on older self-hosted instances and require config-key anchors for
 *   reliable detection. Runner registration tokens (glrt-) are particularly sensitive
 *   as they allow an attacker to register a rogue runner that intercepts CI/CD jobs,
 *   exfiltrates secrets, and injects malicious build steps.
 */

rule GitLab_Personal_Access_Token
{
    meta:
        description    = "Detects GitLab Personal Access Tokens (glpat- prefix, introduced in GitLab 14.5)"
        author         = "BERTON Jules - MORETTI Enzo"
        date           = "2026-03-19"
        version        = "1.0"
        reference      = "https://docs.gitlab.com/ee/security/tokens/token_troubleshooting.html"
        confidence     = "HIGH"
        false_positive = "LOW"
        severity       = "CRITICAL"
        tags           = "gitlab,token,pat,personal-access-token"

    strings:
        // Prefixed PAT (GitLab 14.5+): glpat- + 20 alphanumeric chars
        $glpat = /glpat-[A-Za-z0-9_\-]{20}/

        // Legacy un-prefixed PAT in config context
        $legacy = /(?:gitlab|gl)[_\-\.]?(?:token|pat|access[_\-\.]?token)\s*[=:"']{1,3}\s*['"]?[A-Za-z0-9_\-]{20}['"]?/  nocase

        // Git URL with embedded token
        $git_url = /https:\/\/(?:oauth2|[a-zA-Z0-9_\-\.]+):[A-Za-z0-9_\-]{20}@gitlab\.com/

    condition:
        any of them
}


rule GitLab_Deploy_Token
{
    meta:
        description    = "Detects GitLab Deploy Tokens (gldt-) used for registry and repository read access in CI/CD pipelines"
        author         = "BERTON Jules - MORETTI Enzo"
        date           = "2026-03-19"
        version        = "1.0"
        reference      = "https://docs.gitlab.com/ee/user/project/deploy_tokens/"
        confidence     = "HIGH"
        false_positive = "LOW"
        severity       = "HIGH"
        tags           = "gitlab,deploy-token,ci-cd"

    strings:
        // Deploy Token: gldt- + 20 alphanumeric chars
        $gldt = /gldt-[A-Za-z0-9_\-]{20}/

        // Config anchor for un-prefixed deploy token
        $ctx = /gitlab[_\-\.]?deploy[_\-\.]?token\s*[=:"']{1,3}\s*['"]?[A-Za-z0-9_\-]{20}['"]?/  nocase

    condition:
        any of them
}


rule GitLab_CI_Job_Token
{
    meta:
        description    = "Detects GitLab CI/CD Bridge tokens (glcbt-) and hardcoded CI_JOB_TOKEN references in scripts"
        author         = "BERTON Jules - MORETTI Enzo"
        date           = "2026-03-19"
        version        = "1.0"
        reference      = "https://docs.gitlab.com/ee/ci/jobs/ci_job_token.html"
        confidence     = "HIGH"
        false_positive = "LOW"
        severity       = "HIGH"
        tags           = "gitlab,ci-job-token,ci-cd,pipeline"

    strings:
        // CI/CD Bridge token prefix
        $glcbt = /glcbt-[A-Za-z0-9_\-]{20}/

        // Hardcoded CI_JOB_TOKEN value (should be injected by GitLab at runtime)
        $ci_token = /CI_JOB_TOKEN\s*[=:"']{1,3}\s*['"]?[A-Za-z0-9_\-]{20}['"]?/  nocase

    condition:
        any of them
}


rule GitLab_Service_Account_Token
{
    meta:
        description    = "Detects GitLab Service Account tokens (glsoat-) used for automated non-human access"
        author         = "BERTON Jules - MORETTI Enzo"
        date           = "2026-03-19"
        version        = "1.0"
        reference      = "https://docs.gitlab.com/ee/user/profile/service_accounts.html"
        confidence     = "HIGH"
        false_positive = "LOW"
        severity       = "CRITICAL"
        tags           = "gitlab,service-account,token"

    strings:
        // Service Account token: glsoat- + 20 alphanumeric chars
        $glsoat = /glsoat-[A-Za-z0-9_\-]{20}/

    condition:
        $glsoat
}


rule GitLab_Agent_Token
{
    meta:
        description    = "Detects GitLab Agent for Kubernetes tokens (glagent-) — grants cluster-level access"
        author         = "BERTON Jules - MORETTI Enzo"
        date           = "2026-03-19"
        version        = "1.0"
        reference      = "https://docs.gitlab.com/ee/user/clusters/agent/"
        confidence     = "HIGH"
        false_positive = "LOW"
        severity       = "CRITICAL"
        tags           = "gitlab,agent,kubernetes,token"

    strings:
        // Agent token: glagent- + 50+ alphanumeric chars
        $glagent = /glagent-[A-Za-z0-9_\-]{50,}/

    condition:
        $glagent
}


rule GitLab_Runner_Registration_Token
{
    meta:
        description    = "Detects GitLab Runner registration tokens — allows attacker-controlled runners to intercept CI/CD jobs"
        author         = "BERTON Jules - MORETTI Enzo"
        date           = "2026-03-19"
        version        = "1.0"
        reference      = "https://docs.gitlab.com/runner/register/"
        confidence     = "MEDIUM"
        false_positive = "MEDIUM"
        severity       = "HIGH"
        tags           = "gitlab,runner,registration-token,ci-cd"

    strings:
        // Runner registration token anchor in config.toml or CI env
        $toml_token = /registration[_\-]?token\s*=\s*['"]?[A-Za-z0-9_\-]{20}['"]?/  nocase
        $env_token  = /GITLAB[_\.]?RUNNER[_\.]?TOKEN\s*=\s*['"]?[A-Za-z0-9_\-]{20}['"]?/  nocase

        // glrt- prefix = new runner authentication token (GitLab 15.10+)
        $glrt = /glrt-[A-Za-z0-9_\-]{20}/

    condition:
        any of them
}
