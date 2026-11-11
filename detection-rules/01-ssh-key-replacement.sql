-- Rule: SSH key replacement (MITRE ATT&CK T1098.004)
-- Flags Cowrie sessions that wipe ~/.ssh and write the attacker's own key into authorized_keys.
-- Built on week 1 data (before 9 Oct 2026 12:00), tested on week 2 against a week 1 IP blocklist.
-- Database: DuckDB. Result on week 2: rule 497/509 (97.6%), blocklist 93/509 (18.3%).

SELECT
    count(DISTINCT session) AS attack_sessions,

    -- Behaviour rule: all four steps of the attack appear in the command
    count(DISTINCT CASE WHEN input LIKE '%rm -rf .ssh%'
                          AND input LIKE '%mkdir .ssh%'
                          AND input LIKE '%authorized_keys%'
                          AND input LIKE '%ssh-rsa%'
                        THEN session END) AS rule_caught,

    -- Baseline: block every IP that wrote to authorized_keys in week 1
    count(DISTINCT CASE WHEN src_ip IN (
            SELECT src_ip FROM f.cowrie
            WHERE timestamp < '2026-10-09T12:00:00'
              AND input LIKE '%authorized_keys%')
        THEN session END) AS blocklist_caught

FROM f.cowrie
WHERE timestamp >= '2026-10-09T12:00:00'
  AND input LIKE '%authorized_keys%';
