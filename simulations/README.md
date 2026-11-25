# Synthetic telemetry

Generated with `invariant simulate all -o simulations`. Normalized JSONL, one event per line.
These files are telemetry replays modeled on public reporting, not malware. They use documentation IP
ranges and contain no real keys; the Nacos token is signed with the vendor's *public default* key on purpose,
because detecting that is the point.

    invariant detect --events simulations/jadepuffer.jsonl --respond
