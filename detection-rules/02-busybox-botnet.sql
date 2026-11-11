-- Rule: BusyBox / Mirai-family botnet (MITRE ATT&CK T1059.004, T1105, T1222.002)
-- Flags the "busybox BOTNET" check the bot runs before downloading and running its script.
-- Built on week 1 data, tested on week 2 against a week 1 IP blocklist.
-- Database: DuckDB. Result on week 2: rule 1,099/1,136 (96.7%), blocklist 1,136/1,136 (100%).
-- The blocklist wins here only because every session came from a single IP.

SELECT
    count(DISTINCT session) AS attack_sessions,

    -- Behaviour rule: the bot's fingerprinting command
    count(DISTINCT CASE WHEN input LIKE '%busybox BOTNET%'
                        THEN session END) AS rule_caught,

    -- Baseline: block every IP that ran the command in week 1
    count(DISTINCT CASE WHEN src_ip IN (
            SELECT src_ip FROM f.cowrie
            WHERE timestamp < '2026-10-09T12:00:00'
              AND input LIKE '%busybox BOTNET%')
        THEN session END) AS blocklist_caught

FROM f.cowrie
WHERE timestamp >= '2026-10-09T12:00:00'
  AND eventid = 'cowrie.command.input'
  AND src_ip = '160.119.66.206';
