/*
   Invariant Defense - L2 model dependency: embedded provider API keys.

   LLM-enabled malware must authenticate to the model it calls. Its key is a
   stable artifact even when every other byte is regenerated. Use these rules
   for retrohunting sample stores and scanning endpoints/repos.

   Formats follow public secret-scanning rule sets (gitleaks, GitLab secret
   detection, provider documentation). A hit is a lead: confirm, then revoke
   with the provider (pre-agree the revocation path before you need it).
*/

rule INV_LLM_Key_Anthropic
{
    meta:
        author = "invariant-defense"
        layer = "L2"
        description = "Anthropic API or admin key"
        severity = "high"
    strings:
        $k = /sk-ant-(api03|admin01)-[A-Za-z0-9_\-]{93}AA/ ascii wide
    condition:
        $k
}

rule INV_LLM_Key_OpenAI
{
    meta:
        author = "invariant-defense"
        layer = "L2"
        description = "OpenAI project/service/admin or legacy key (contains the T3BlbkFJ marker, base64 of 'OpenAI')"
        severity = "high"
    strings:
        $proj = /sk-(proj|svcacct|admin)-[A-Za-z0-9_\-]{20,200}T3BlbkFJ[A-Za-z0-9_\-]{20,200}/ ascii wide
        $legacy = /sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}/ ascii wide
    condition:
        any of them
}

rule INV_LLM_Key_Google_Gemini
{
    meta:
        author = "invariant-defense"
        layer = "L2"
        description = "Google API key next to a Gemini/Vertex endpoint (PROMPTFLUX embedded one)"
        severity = "high"
    strings:
        $k = /AIza[0-9A-Za-z_\-]{35}/ ascii wide
        $e1 = "generativelanguage.googleapis.com" ascii wide nocase
        $e2 = "aiplatform.googleapis.com" ascii wide nocase
        $e3 = ":generateContent" ascii wide nocase
    condition:
        $k and any of ($e*)
}

rule INV_LLM_Key_HuggingFace
{
    meta:
        author = "invariant-defense"
        layer = "L2"
        description = "Hugging Face access token (LAMEHUG/PROMPTSTEAL used the HF inference API)"
        severity = "high"
    strings:
        $k = /hf_[A-Za-z0-9]{34,40}/ ascii wide
    condition:
        $k
}

rule INV_LLM_Key_Routers
{
    meta:
        author = "invariant-defense"
        layer = "L2"
        description = "Keys for inference routers and fast-inference providers"
        severity = "high"
    strings:
        $openrouter = /sk-or-v1-[a-f0-9]{64}/ ascii wide
        $groq = /gsk_[A-Za-z0-9]{52}/ ascii wide
        $xai = /xai-[A-Za-z0-9]{80}/ ascii wide
        $replicate = /r8_[A-Za-z0-9]{37}/ ascii wide
        $pplx = /pplx-[A-Za-z0-9]{48}/ ascii wide
    condition:
        any of them
}

rule INV_LLM_Multiple_Provider_Keys
{
    meta:
        author = "invariant-defense"
        layer = "L2"
        description = "Several provider keys in one file: fallback logic common in LLM-enabled tooling and malware"
        severity = "critical"
    strings:
        $a = /sk-ant-(api03|admin01)-[A-Za-z0-9_\-]{93}AA/ ascii wide
        $o = /sk-[A-Za-z0-9_\-]{20,200}T3BlbkFJ/ ascii wide
        $g = /AIza[0-9A-Za-z_\-]{35}/ ascii wide
        $h = /hf_[A-Za-z0-9]{34,40}/ ascii wide
        $r = /sk-or-v1-[a-f0-9]{64}/ ascii wide
    condition:
        2 of them
}
