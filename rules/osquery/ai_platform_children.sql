-- Invariant L3 (Linux/macOS): shells, downloaders and decoders whose parent runs an AI platform.
SELECT c.pid, c.name, c.cmdline, p.pid AS parent_pid, p.cmdline AS parent_cmdline
FROM processes c
JOIN processes p ON c.parent = p.pid
WHERE (p.cmdline LIKE '%langflow%' OR p.cmdline LIKE '%flowise%' OR p.cmdline LIKE '%n8n%'
       OR p.cmdline LIKE '%dify%' OR p.cmdline LIKE '%comfyui%' OR p.cmdline LIKE '%open-webui%')
  AND c.name IN ('sh', 'bash', 'dash', 'curl', 'wget', 'base64', 'nc', 'ncat', 'socat', 'python3', 'perl');
