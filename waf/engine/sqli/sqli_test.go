package sqli

import (
	"strings"
	"testing"
)

// positives must all be detected. one per line, real payloads.
var positives = []string{
	"' or '1'='1",
	"' or 1=1--",
	"' or 1=1#",
	"' or 1=1/*",
	"') or ('1'='1",
	"') or ('a'='a",
	"1' or '1'='1",
	"admin'--",
	"admin' --",
	"admin'#",
	"admin'/*",
	"' or ''='",
	"\" or \"\"=\"",
	"' or 1=1 limit 1--",
	"' union select null,null--",
	"' union select username,password from users--",
	"1 union select 1,2,3",
	"union all select null",
	"/*!50000union*/ select 1",
	"' UNION SELECT 1,2,3-- -",
	"1; drop table users",
	"'; drop table users--",
	"1; exec xp_cmdshell('dir')",
	"'; shutdown--",
	"1 and 1=1",
	"1 and 1=2",
	"' and '1'='1",
	"' and substring(@@version,1,1)=5--",
	"' and ascii(substring((select password from users limit 1),1,1))>64--",
	"1 or sleep(5)",
	"' or sleep(5)--",
	"'; waitfor delay '0:0:5'--",
	"1) or benchmark(1000000,md5('a'))--",
	"' or pg_sleep(5)--",
	"1 and (select 1 from(select count(*),concat(version(),floor(rand(0)*2))x from information_schema.tables group by x)a)",
	"' and extractvalue(1,concat(0x7e,version()))--",
	"' and updatexml(1,concat(0x7e,(select user())),1)--",
	"1' and if(1=1,sleep(5),0)-- -",
	"' or 1=1 or ''='",
	"1 or 1=1",
	"' or 'x'='x",
	"' or 'a'='a'--",
	"1' order by 100--",
	"' having 1=1--",
	"' group by columnnames having 1=1--",
	"1 procedure analyse(extractvalue(1,concat(0x7e,version())),1)",
	"' union select @@version--",
	"' union all select load_file('/etc/passwd')--",
	"' into outfile '/tmp/x'--",
	"1'||'1",
	"' or 1=1 #",
	"') or 1=1--",
	"')) or (('1'='1",
	"1%' or '1%'='1",
	"' oR '1'='1",
	"' Or 1=1--",
	"x' AND 1=(SELECT COUNT(*) FROM tabname); --",
	"' union select table_name from information_schema.tables--",
	"' or username is not null--",
	"1' and 1=1 union select 1,2,version()--",
	"cat' or 1=1 or 'x'='x",
}

// negatives must all pass. real human input.
var negatives = []string{
	"grant writing tips",
	"how to drop a table in excel",
	"select the best laptop under 1000",
	"the union strike update",
	"difference between cats and dogs",
	"do you like cats or dogs",
	"or true and false in python",
	"exec summary of the report",
	"i want to order by tuesday",
	"where is the nearest cafe",
	"insert coin to continue",
	"delete my account please",
	"create a new group",
	"update on the merger",
	"john's car",
	"it's a beautiful day",
	"the cat's toy",
	"O'Brien",
	"D'Angelo",
	"can't won't don't",
	"rock 'n' roll",
	"she said \"hello\" to me",
	"price is 10 or 20 dollars",
	"between you and me",
	"5 and 10 percent off",
	"select from the menu and enjoy",
	"drop off the kids",
	"having fun at the beach",
	"is this the real life",
	"a or b, and c",
	"1 + 1 = 2 is true",
	"my email is a@b.com",
	"visit http://example.com/path?a=1&b=2",
	"SELECT * FROM should be quoted in a code field",
	"union of concerned scientists",
	"the group by the river",
	"i like turtles",
	"search for shoes",
	"2024-01-01 to 2024-02-01",
	"call me at 555-1234",
	"see section 1.2.3",
	"hello world",
	"admin",
	"password123",
	"true story",
	"null pointer exception",
	"C++ and Java",
	"a && b in my notes",
}

func TestPositives(t *testing.T) {
	miss := 0
	for _, p := range positives {
		if _, ok := Detect([]byte(p)); !ok {
			t.Errorf("MISS: %q", p)
			miss++
		}
	}
	if miss > 0 {
		t.Logf("%d/%d positives missed", miss, len(positives))
	}
}

func TestNegatives(t *testing.T) {
	fp := 0
	for _, n := range negatives {
		if r, ok := Detect([]byte(n)); ok {
			t.Errorf("FALSE POSITIVE: %q -> %s (%s)", n, r.Reason, r.Fingerprint)
			fp++
		}
	}
	if fp > 0 {
		t.Logf("%d/%d false positives", fp, len(negatives))
	}
}

func TestTokenizeSmoke(t *testing.T) {
	toks := Tokenize([]byte("1 or 1=1"), CtxNone, nil)
	if len(toks) == 0 {
		t.Fatal("no tokens")
	}
	got := Fingerprint(Fold(toks, nil))
	if !strings.HasPrefix(got, "n&") {
		t.Fatalf("fingerprint %q", got)
	}
}

func FuzzDetect(f *testing.F) {
	for _, p := range positives {
		f.Add(p)
	}
	for _, n := range negatives {
		f.Add(n)
	}
	f.Fuzz(func(t *testing.T, s string) {
		Detect([]byte(s)) // must not panic or loop
	})
}

func BenchmarkDetectBenign(b *testing.B) {
	in := []byte("visit http://example.com/path?a=1&b=2 and search for shoes")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Detect(in)
	}
}

func BenchmarkDetectAttack(b *testing.B) {
	in := []byte("' union select username,password from users where '1'='1")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Detect(in)
	}
}
