/*
 * YARA Rules: Microsoft Copilot / GitHub Copilot Credentials
 *
 * Date        : 19-03-2026
 * Version     : 1.0
 * Reference   : https://docs.github.com/en/copilot/how-tos/copilot-cli/set-up-copilot-cli/authenticate-copilot-cli
 *               https://learn.microsoft.com/en-us/copilot/security/plugin-api
 *
 * Coverage:
 *   - GitHub Copilot CLI tokens (COPILOT_GITHUB_TOKEN env var)
 *   - GitHub Copilot OAuth stored config (~/.copilot/config.json)
 *   - Microsoft 365 Copilot plugin API keys (Security Copilot / Copilot Studio)
 *   - Azure OpenAI keys used by Copilot backends (Chat Copilot / chat-copilot)
 *   - GitHub PAT with Copilot billing scope (manage_billing:copilot)
 *
 * Architecture notes:
 *   GitHub Copilot (the code assistant) authenticates via:
 *     1. COPILOT_GITHUB_TOKEN env var  — takes precedence
 *     2. GH_TOKEN / GITHUB_TOKEN       — fallback
 *     3. OAuth device flow             — stored in ~/.copilot/config.json
 *   All three resolve to a GitHub PAT or OAuth token (ghp_, gho_ prefix).
 *
 *   Microsoft Security Copilot plugins use a custom API key registered
 *   through the Copilot plugin manifest. The key itself is free-form
 *   (10-2048 chars), so detection relies on the manifest structure.
 *
 *   Microsoft 365 Copilot (the chat assistant) does NOT have a public API key.
 *   It uses Azure AD / Microsoft Entra ID tokens (covered by azure.yar).
 *
 *   Chat Copilot (microsoft/chat-copilot on GitHub) is a self-hosted app
 *   that requires an OpenAI or Azure OpenAI API key — those are covered
 *   in openai.yar and azure.yar respectively. Rules here detect the
 *   Chat Copilot configuration context to flag the surrounding key.
 */

rule GitHub_Copilot_Token_Env
{
    meta:
        description    = "Detects GitHub Copilot CLI authentication tokens in environment variables or CI/CD config"
        author         = "yara-apikey-rules"
        date           = "2025-03-03"
        version        = "1.0"
        reference      = "https://docs.github.com/en/copilot/how-tos/copilot-cli/set-up-copilot-cli/authenticate-copilot-cli"
        confidence     = "HIGH"
        false_positive = "LOW"
        severity       = "HIGH"
        tags           = "copilot,github,token,env,ci-cd"

    strings:
        // Primary Copilot CLI env var — overrides all other tokens
        $cop_token    = /COPILOT_GITHUB_TOKEN\s*=\s*['"]?(?:ghp_|gho_|github_pat_)[A-Za-z0-9_]{30,}['"]?/

        // Fallback env vars used by Copilot CLI
        $gh_token     = /GH_TOKEN\s*=\s*['"]?(?:ghp_|gho_)[A-Za-z0-9]{36}['"]?/
        $github_token = /GITHUB_TOKEN\s*=\s*['"]?(?:ghp_|gho_)[A-Za-z0-9]{36}['"]?/

    condition:
        any of them
}


rule GitHub_Copilot_OAuth_Config_File
{
    meta:
        description    = "Detects GitHub Copilot CLI OAuth token stored in ~/.copilot/config.json"
        author         = "yara-apikey-rules"
        date           = "2025-03-03"
        version        = "1.0"
        reference      = "https://docs.github.com/en/copilot/how-tos/copilot-cli/set-up-copilot-cli/authenticate-copilot-cli"
        confidence     = "HIGH"
        false_positive = "LOW"
        severity       = "HIGH"
        tags           = "copilot,github,oauth,config-file"

    strings:
        // Copilot CLI config file structure
        $config_key   = "copilot-cli"

        // OAuth token fields in config.json
        $token_field  = /"(?:oauth_token|token|access_token)"\s*:\s*"(?:ghp_|gho_)[A-Za-z0-9]{36}"/
        $token_field2 = /"(?:oauth_token|token|access_token)"\s*:\s*"github_pat_[A-Za-z0-9_]{82}"/

        // GitHub.com host context
        $host_field   = "\"github.com\""

    condition:
        ($config_key or $host_field) and any of ($token_field*)
}


rule Microsoft_Security_Copilot_Plugin_API_Key
{
    meta:
        description    = "Detects Microsoft Security Copilot plugin manifest with API key authentication"
        author         = "yara-apikey-rules"
        date           = "2025-03-03"
        version        = "1.0"
        reference      = "https://learn.microsoft.com/en-us/copilot/security/plugin-api"
        confidence     = "HIGH"
        false_positive = "LOW"
        severity       = "HIGH"
        tags           = "copilot,microsoft,security-copilot,plugin,api-key"

    strings:
        // Plugin manifest authentication type anchors
        $auth_apikey  = "\"Type\": \"ApiKey\""
        $auth_apikey2 = "\"Type\": \"APIKey\""

        // Copilot plugin descriptor structure
        $descriptor   = "DescriptionForModel"
        $skill_group  = "SkillGroups"

        // API key stored as plugin secret
        $api_secret   = /"ApiKey"\s*:\s*"[A-Za-z0-9\-_\.~!@#$%^&*]{10,2048}"/

    condition:
        ($auth_apikey or $auth_apikey2) and ($descriptor or $skill_group or $api_secret)
}


rule GitHub_Copilot_PAT_Billing_Scope
{
    meta:
        description    = "Detects GitHub PAT tokens with Copilot billing management scope (manage_billing:copilot)"
        author         = "yara-apikey-rules"
        date           = "2025-03-03"
        version        = "1.0"
        reference      = "https://www.stitchflow.com/user-management/github-copilot/api"
        confidence     = "MEDIUM"
        false_positive = "MEDIUM"
        severity       = "HIGH"
        tags           = "copilot,github,pat,billing,admin"

    strings:
        // PAT with Copilot billing scope — appears in CI/CD or admin scripts
        $scope_comment  = "manage_billing:copilot"
        $scope_ref      = "copilot/billing"

        // Classic PAT nearby
        $pat_classic    = /ghp_[A-Za-z0-9]{36}/
        $pat_fine       = /github_pat_[A-Za-z0-9_]{82}/

        // API endpoint patterns for Copilot billing management
        $endpoint       = /\/orgs\/[^\/]+\/copilot\/billing/
        $endpoint2      = /\/enterprises\/[^\/]+\/copilot\/billing/

    condition:
        ($scope_comment or $scope_ref or $endpoint or $endpoint2)
        and ($pat_classic or $pat_fine)
}


rule Chat_Copilot_Backend_Config
{
    meta:
        description    = "Detects microsoft/chat-copilot backend configuration containing AI API keys"
        author         = "yara-apikey-rules"
        date           = "2025-03-03"
        version        = "1.0"
        reference      = "https://github.com/microsoft/chat-copilot"
        confidence     = "MEDIUM"
        false_positive = "LOW"
        severity       = "CRITICAL"
        tags           = "copilot,microsoft,chat-copilot,openai,azure-openai,config"

    strings:
        // Chat Copilot appsettings.json structure
        $kernel_section = "\"KernelMemory\""
        $ai_section     = "\"AIServices\""

        // OpenAI key in Chat Copilot config
        $openai_key     = /"API_KEY"\s*:\s*"sk-[A-Za-z0-9_\-]{20,74}T3BlbkFJ[A-Za-z0-9_\-]{20,74}"/

        // Azure OpenAI key in Chat Copilot config
        $azure_key      = /"API_KEY"\s*:\s*"[0-9a-f]{32}"/
        $azure_ep       = /"AZURE_OPENAI_ENDPOINT"\s*:\s*"https:\/\/[^"]+\.openai\.azure\.com"/

    condition:
        ($kernel_section or $ai_section) and any of ($openai_key, $azure_key, $azure_ep)
}
