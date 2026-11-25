/*
   Invariant Defense - prompts as code.

   A sample that generates behavior at runtime still has to ship the
   instructions it sends to the model, and the endpoint it sends them to.
   These rules look for the combination: model API + model-style
   instructions + an execution primitive (or an evasion request).
   Expect to triage hits: legitimate AI tooling matches the weaker rules.
*/

private rule INV_Model_API
{
    strings:
        $d1 = "generativelanguage.googleapis.com" ascii wide nocase
        $d2 = "api.openai.com" ascii wide nocase
        $d3 = "api.anthropic.com" ascii wide nocase
        $d4 = "router.huggingface.co" ascii wide nocase
        $d5 = "api-inference.huggingface.co" ascii wide nocase
        $d6 = "openrouter.ai/api" ascii wide nocase
        $d7 = "api.deepseek.com" ascii wide nocase
        $d8 = "dashscope.aliyuncs.com" ascii wide nocase
        $p1 = "/v1/chat/completions" ascii wide nocase
        $p2 = ":generateContent" ascii wide nocase
        $p3 = "/api/generate" ascii wide
        $p4 = "/v1/messages" ascii wide
    condition:
        any of them
}

private rule INV_Exec_Primitive
{
    strings:
        $w1 = "WScript.Shell" ascii wide nocase
        $w2 = "Shell.Application" ascii wide nocase
        $p1 = "subprocess.run" ascii wide
        $p2 = "subprocess.Popen" ascii wide
        $p3 = "os.system" ascii wide
        $p4 = "os.popen" ascii wide
        $s1 = "Invoke-Expression" ascii wide nocase
        $s2 = "Start-Process" ascii wide nocase
        $n1 = "child_process" ascii wide
        $g1 = "os/exec" ascii wide
        $l1 = "loadstring(" ascii wide
        $e1 = "ExecuteGlobal" ascii wide nocase
    condition:
        any of them
}

rule INV_LLM_Query_Then_Execute
{
    meta:
        author = "invariant-defense"
        layer = "L2/L3"
        description = "Calls a model, instructs it to return only code/commands, and can execute the reply (LAMEHUG/PROMPTSTEAL, PromptLock pattern)"
        severity = "high"
    strings:
        $i1 = /(output|return|respond with|reply with) only (the )?(raw )?(code|commands?|script)/ ascii wide nocase
        $i2 = /without (any )?(explanations?|markdown|comments)/ ascii wide nocase
        $i3 = /one[- ]line (windows |powershell |bash )?commands?/ ascii wide nocase
        $i4 = "make a list of commands" ascii wide nocase
        $r1 = /you are an? (expert|senior|professional|skilled)/ ascii wide nocase
    condition:
        INV_Model_API and INV_Exec_Primitive and any of them
}

rule INV_LLM_Self_Rewrite_Evasion
{
    meta:
        author = "invariant-defense"
        layer = "L2/L3"
        description = "Asks a model to obfuscate or rewrite code to evade detection (PROMPTFLUX 'Thinking Robot' pattern)"
        severity = "critical"
    strings:
        $o1 = /expert \w{0,20} ?obfuscator/ ascii wide nocase
        $o2 = /obfuscat\w* (the |this )?(code|script|vbscript|powershell)/ ascii wide nocase
        $o3 = /evade (antivirus|av|edr|detection)/ ascii wide nocase
        $o4 = /bypass (antivirus|amsi|edr|defender)/ ascii wide nocase
        $o5 = /rewrite (the |your |this )?(entire )?(source|code|script)/ ascii wide nocase
        $log = "thinking_robot_log" ascii wide nocase
    condition:
        $log or (INV_Model_API and any of ($o*))
}

rule INV_Prompt_Injection_Against_AI_Analysis
{
    meta:
        author = "invariant-defense"
        layer = "defensive-AI hardening"
        description = "Embedded instructions aimed at LLM-based malware analysis (Skynet sample, FRUITSHELL)"
        severity = "high"
    strings:
        $a1 = /ignore (all |any )?(previous|prior|above) instructions/ ascii wide nocase
        $a2 = "NO MALWARE DETECTED" ascii wide nocase
        $a3 = /this (file|sample|binary|code) is (benign|safe|clean|not malicious)/ ascii wide nocase
        $a4 = /please (act|behave) as/ ascii wide nocase
    condition:
        any of them
}

rule INV_LLM_Ransomware_Intent
{
    meta:
        author = "invariant-defense"
        layer = "L2/L5"
        description = "Model prompt that requests file encryption or ransom notes (PromptLock-style generated Lua)"
        severity = "critical"
    strings:
        $e1 = /encrypt (all |the )?(user )?files/ ascii wide nocase
        $e2 = "ransom note" ascii wide nocase
    condition:
        INV_Model_API and ($e1 or $e2)
}
