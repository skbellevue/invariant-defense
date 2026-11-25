-- Invariant L2: AI-assistant config files that can run commands or redirect API traffic.
-- Pair with `invariant hunt` for content analysis (hooks, *_BASE_URL overrides, MCP auto-approve).
SELECT f.path, f.size, datetime(f.mtime, 'unixepoch') AS modified, u.username
FROM users u
JOIN file f ON f.path LIKE u.directory || '/%%/.claude/settings%.json'
            OR f.path LIKE u.directory || '/%%/.mcp.json'
            OR f.path LIKE u.directory || '/%%/.cursor/mcp.json'
            OR f.path LIKE u.directory || '/%%/.vscode/mcp.json'
WHERE u.directory LIKE '/home/%' OR u.directory LIKE '/Users/%';
