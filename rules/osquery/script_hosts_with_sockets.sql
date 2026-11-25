-- Invariant L2 (Windows): script hosts and Office holding outbound TLS sockets.
-- Resolve remote_address against your LLM endpoint IP list or DNS logs.
SELECT p.pid, p.name, p.path, p.cmdline, s.remote_address, s.remote_port
FROM processes p
JOIN process_open_sockets s USING (pid)
WHERE lower(p.name) IN ('wscript.exe', 'cscript.exe', 'mshta.exe', 'powershell.exe', 'pwsh.exe',
                        'rundll32.exe', 'regsvr32.exe', 'winword.exe', 'excel.exe')
  AND s.remote_port = 443
  AND s.remote_address NOT IN ('127.0.0.1', '::1', '0.0.0.0', '');
