/*
 * YARA Rules: Google Gemini API Credentials
 *
 * Author      : BERTON Jules - MORETTI Enzo
 * Date        : 19-03-2026
 * Version     : 1.0
 * Reference   : https://ai.google.dev/gemini-api/docs/api-key
 *               https://trufflesecurity.com/blog/google-api-keys-werent-secrets-but-then-gemini-changed-the-rules
 *               https://www.theregister.com/2026/03/03/gemini_api_key_82314_dollar_charge/
 *
 * Coverage:
 *   - Gemini / Google AI Studio API keys    (AIza prefix — shared with all GCP APIs)
 *   - GEMINI_API_KEY / GOOGLE_API_KEY env vars scoped to Gemini
 *   - Vertex AI service account JSON keys (Gemini on GCP context)
 *   - Gemini API endpoint context detection
 *
 * CRITICAL THREAT CONTEXT (TruffleSecurity, March 2026):
 *   Google uses the same AIza... key format for ALL GCP APIs — Maps, Firebase,
 *   YouTube, AND Gemini. For years, Google stated these keys were safe to embed
 *   publicly in HTML (they were billing identifiers, not auth tokens).
 *
 *   When Gemini launched, existing public AIza... keys silently gained access to:
 *     - Uploaded files and datasets (/v1beta/files)
 *     - Cached context and conversations (/v1beta/cachedContents)
 *     - Generative Language API (billing: up to $82,314 per incident observed)
 *
 *   TruffleSecurity found 2,863 live Gemini-capable keys in the Nov 2025
 *   Common Crawl dataset — embedded in public HTML following Google's own docs.
 *   Source: The Register, March 3 2026.
 *
 *   Recommendation: ALL AIza... keys should now be treated as potential Gemini
 *   credentials regardless of their original intended use.
 *
 * Environment variables:
 *   GEMINI_API_KEY    (Gemini CLI, google-generativeai SDK)
 *   GOOGLE_API_KEY    (legacy, same key, broader scope)
 *   GOOGLE_CLOUD_PROJECT + GOOGLE_CLOUD_LOCATION (Vertex AI context)
 */

rule Gemini_API_Key_Standard
{
    meta:
        description    = "Detects Google Gemini / GCP API keys (AIza prefix) — HIGH RISK: may grant Gemini AI access even if created for Maps/Firebase"
        author         = "BERTON Jules - MORETTI Enzo"
        date           = "19-03-2026"
        version        = "1.0"
        reference      = "https://trufflesecurity.com/blog/google-api-keys-werent-secrets-but-then-gemini-changed-the-rules"
        confidence     = "HIGH"
        false_positive = "LOW"
        severity       = "CRITICAL"
        tags           = "gemini,google,gcp,api-key,llm,maps,firebase"

    strings:
        // All Google API keys use AIza prefix followed by 35 alphanumeric chars
        // This covers Gemini, Maps, Firebase, YouTube, and all other GCP APIs
        $api_key    = /AIza[0-9A-Za-z\-_]{35}/

    condition:
        $api_key
}


rule Gemini_API_Key_In_Config
{
    meta:
        description    = "Detects Gemini API keys in config files and env vars (GEMINI_API_KEY / GOOGLE_API_KEY)"
        author         = "BERTON Jules - MORETTI Enzo"
        date           = "19-03-2026"
        version        = "1.0"
        reference      = "https://ai.google.dev/gemini-api/docs/api-key"
        confidence     = "HIGH"
        false_positive = "LOW"
        severity       = "CRITICAL"
        tags           = "gemini,google,api-key,config,env"

    strings:
        // Gemini CLI and google-generativeai SDK canonical env vars
        $env1     = /GEMINI_API_KEY[ \t]*=[ \t]*['"]?AIza[0-9A-Za-z\-_]{35}['"]?/
        $env2     = /GOOGLE_API_KEY[ \t]*=[ \t]*['"]?AIza[0-9A-Za-z\-_]{35}['"]?/

        // JSON config — gemini variant (e.g. "gemini_api_key", "gemini-api-key")
        $json1a   = /"gemini[_\-]?api[_\-]?key"[ \t]*:[ \t]*"AIza[0-9A-Za-z\-_]{35}"/ nocase
        // JSON config — google variant (e.g. "google_api_key", "google-api-key")
        $json1b   = /"google[_\-]?api[_\-]?key"[ \t]*:[ \t]*"AIza[0-9A-Za-z\-_]{35}"/ nocase

        // Python SDK (google-generativeai)
        $sdk_py   = /genai\.configure[ \t]*\([ \t]*api_key[ \t]*=[ \t]*['"]AIza[0-9A-Za-z\-_]{35}['"]/

        // query parameter in URL (very common in public JS code)
        $url_key  = /[?&]key=AIza[0-9A-Za-z\-_]{35}/

    condition:
        any of them
}


rule Gemini_API_Endpoint_With_Key
{
    meta:
        description    = "Detects Gemini API endpoint calls with embedded API key — indicates direct usage context"
        author         = "BERTON Jules - MORETTI Enzo"
        date           = "19-03-2026"
        version        = "1.0"
        reference      = "https://ai.google.dev/gemini-api/docs/api-reference"
        confidence     = "HIGH"
        false_positive = "LOW"
        severity       = "CRITICAL"
        tags           = "gemini,google,api-endpoint,api-key"

    strings:
        // Direct API call to generativelanguage.googleapis.com with key param
        $endpoint1  = /generativelanguage\.googleapis\.com[^"'\s]{0,100}[?&]key=AIza[0-9A-Za-z\-_]{35}/

        // AI Studio / Vertex AI Gemini endpoint
        $endpoint2  = /aiplatform\.googleapis\.com[^"'\s]{0,100}[?&]key=AIza[0-9A-Za-z\-_]{35}/

        // Files API endpoint (high value — can expose uploaded datasets)
        $endpoint3  = /generativelanguage\.googleapis\.com\/v1beta\/files[^"'\s]{0,100}[?&]key=AIza/

    condition:
        any of them
}


rule Gemini_Vertex_AI_Service_Account
{
    meta:
        description    = "Detects Vertex AI / Gemini service account JSON key files (production auth method)"
        author         = "BERTON Jules - MORETTI Enzo"
        date           = "19-03-2026"
        version        = "1.0"
        reference      = "https://geminicli.com/docs/get-started/authentication/"
        confidence     = "HIGH"
        false_positive = "LOW"
        severity       = "CRITICAL"
        tags           = "gemini,vertex-ai,gcp,service-account,credential-file"

    strings:
        // Service account JSON — type anchor
        $type         = "\"type\": \"service_account\""

        // Vertex AI specific role/scope indicators
        $vertex_role  = "roles/aiplatform"
        $vertex_scope = "https://www.googleapis.com/auth/cloud-platform"

        // Private key block
        $private_key  = "-----BEGIN RSA PRIVATE KEY-----"
        $private_key2 = "-----BEGIN PRIVATE KEY-----"

        // Vertex AI endpoint reference
        $vertex_ep    = "aiplatform.googleapis.com"

    condition:
        $type and (1 of ($private_key*)) and ($vertex_role or $vertex_scope or $vertex_ep)
}
