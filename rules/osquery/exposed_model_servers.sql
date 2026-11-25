-- Invariant L1: model servers listening on non-loopback addresses (Ollama has no built-in auth).
SELECT lp.port, lp.address, p.name, p.cmdline
FROM listening_ports lp
JOIN processes p USING (pid)
WHERE lp.port IN (11434, 1234, 7860, 8848, 9000, 5678, 3000)
  AND lp.address NOT IN ('127.0.0.1', '::1')
  AND lp.protocol = 6;
