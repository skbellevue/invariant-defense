-- Invariant L3 (Windows): scripts in per-user Startup folders, newest first.
SELECT f.path, f.size, datetime(f.mtime, 'unixepoch') AS modified, h.sha256
FROM file f
JOIN hash h USING (path)
WHERE f.path LIKE 'C:\Users\%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\%'
  AND (f.path LIKE '%.vbs' OR f.path LIKE '%.js' OR f.path LIKE '%.ps1' OR f.path LIKE '%.bat'
       OR f.path LIKE '%.cmd' OR f.path LIKE '%.hta' OR f.path LIKE '%.wsf')
ORDER BY f.mtime DESC;
