package sqli

import "strings"

// Token type letters. They are what a fingerprint is made of, so they are
// single printable bytes on purpose.
const (
	TNumber    = 'n' // 1, 1.5, 0x1f, 1e3, true, false, null
	TString    = 's' // '...' "..." N'..' x'..' $$..$$
	TKeyword   = 'k' // where, from, order by, ...
	TEvil      = 'E' // statement starters: select insert update delete drop ...
	TUnion     = 'U' // union, union all, union distinct
	TFunc      = 'f' // known function name followed by (
	TEvilFunc  = 'X' // sleep( benchmark( xp_cmdshell( load_file( ...
	TOp        = 'o' // = < > + - * like in is between ...
	TLogic     = '&' // and or xor && || not
	TComment   = 'c' // -- # /* */
	TVar       = 'v' // @x @@x :x $x
	TBare      = 'B' // any other word
	TType      = 't' // int, varchar, ... (cast targets)
	TLParen    = '('
	TRParen    = ')'
	TComma     = ','
	TSemi      = ';'
	TDot       = '.'
	TColon     = ':'
	TBackslash = '\\'
)

// strong keywords: the ones that make an E look like a statement rather
// than an english sentence ("delete from", "drop table", "select ... from")
var strongKeyword = map[string]bool{
	"from": true, "into": true, "where": true, "table": true, "database": true,
	"values": true, "set": true, "procedure": true, "function": true, "view": true,
	"schema": true, "index": true, "user": true, "having": true, "limit": true,
	"group by": true, "order by": true, "join": true, "inner join": true,
	"left join": true, "right join": true, "cross join": true, "outer join": true,
	"outfile": true, "dumpfile": true, "infile": true,
}

// keywords maps a lowercased word (or merged pair) to its token type.
var keywords = map[string]byte{
	// statement starters
	"select": TEvil, "insert": TEvil, "update": TEvil, "delete": TEvil, "drop": TEvil,
	"create": TEvil, "alter": TEvil, "truncate": TEvil, "exec": TEvil, "execute": TEvil,
	"shutdown": TEvil, "grant": TEvil, "revoke": TEvil, "declare": TEvil, "merge": TEvil,
	"call": TEvil, "handler": TEvil, "rename": TEvil, "replace": TEvil, "load": TEvil,
	"describe": TEvil, "explain": TEvil, "show": TEvil, "use": TEvil, "kill": TEvil,
	"set": TEvil, "begin": TEvil, "commit": TEvil, "rollback": TEvil, "waitfor": TEvil,
	"insert into": TEvil, "delete from": TEvil, "drop table": TEvil, "drop database": TEvil,
	"create table": TEvil, "alter table": TEvil, "load data": TEvil, "union": TUnion, "union all": TUnion, "union distinct": TUnion,

	// logic
	"and": TLogic, "or": TLogic, "xor": TLogic, "not": TLogic, "&&": TLogic, "||": TLogic,

	// operators spelled as words
	"like": TOp, "rlike": TOp, "regexp": TOp, "ilike": TOp, "similar": TOp, "in": TOp,
	"is": TOp, "between": TOp, "div": TOp, "mod": TOp, "sounds like": TOp,
	"not like": TOp, "not in": TOp, "is not": TOp, "not between": TOp, "not regexp": TOp,
	"binary": TOp, "collate": TOp, "escape": TOp, "any": TOp, "some": TOp, "all": TOp,
	"exists": TOp, "not exists": TOp,

	// literals
	"true": TNumber, "false": TNumber, "null": TNumber, "unknown": TNumber,

	// plain keywords
	"from": TKeyword, "where": TKeyword, "into": TKeyword, "values": TKeyword, "table": TKeyword,
	"database": TKeyword, "order": TKeyword, "group": TKeyword, "by": TKeyword, "having": TKeyword,
	"limit": TKeyword, "offset": TKeyword, "as": TKeyword, "on": TKeyword, "join": TKeyword,
	"inner": TKeyword, "left": TKeyword, "right": TKeyword, "outer": TKeyword, "cross": TKeyword,
	"natural": TKeyword, "using": TKeyword, "distinct": TKeyword, "top": TKeyword, "case": TKeyword,
	"when": TKeyword, "then": TKeyword, "else": TKeyword, "end": TKeyword, "if": TKeyword,
	"iff": TKeyword, "for": TKeyword, "while": TKeyword, "loop": TKeyword, "fetch": TKeyword,
	"cursor": TKeyword, "open": TKeyword, "close": TKeyword, "deallocate": TKeyword,
	"procedure": TKeyword, "function": TKeyword, "trigger": TKeyword, "view": TKeyword,
	"schema": TKeyword, "index": TKeyword, "key": TKeyword, "primary": TKeyword, "foreign": TKeyword,
	"references": TKeyword, "constraint": TKeyword, "default": TKeyword, "unique": TKeyword,
	"check": TKeyword, "cascade": TKeyword, "restrict": TKeyword, "temporary": TKeyword,
	"user": TKeyword, "identified": TKeyword, "password": TKeyword, "privileges": TKeyword,
	"option": TKeyword, "with": TKeyword, "recursive": TKeyword, "window": TKeyword, "over": TKeyword,
	"partition": TKeyword, "rows": TKeyword, "range": TKeyword, "preceding": TKeyword,
	"following": TKeyword, "current": TKeyword, "row": TKeyword, "returning": TKeyword,
	"outfile": TKeyword, "dumpfile": TKeyword, "infile": TKeyword, "lines": TKeyword,
	"terminated": TKeyword, "fields": TKeyword, "enclosed": TKeyword, "delay": TKeyword,
	"time": TKeyword, "dual": TKeyword, "sysobjects": TKeyword, "syscolumns": TKeyword,
	"information_schema": TKeyword, "pg_catalog": TKeyword, "mysql": TKeyword,
	"group by": TKeyword, "order by": TKeyword, "inner join": TKeyword, "left join": TKeyword,
	"right join": TKeyword, "cross join": TKeyword, "outer join": TKeyword, "natural join": TKeyword,
	"full join": TKeyword, "left outer": TKeyword, "right outer": TKeyword, "full outer": TKeyword,
	"waitfor delay": TEvilFunc, "waitfor time": TEvilFunc,

	// types (cast/convert targets)
	"int": TType, "integer": TType, "bigint": TType, "smallint": TType, "tinyint": TType,
	"char": TType, "varchar": TType, "nchar": TType, "nvarchar": TType, "text": TType,
	"date": TType, "datetime": TType, "timestamp": TType, "float": TType, "double": TType,
	"decimal": TType, "numeric": TType, "boolean": TType, "bool": TType, "blob": TType,
	"signed": TType, "unsigned": TType, "json": TType, "xml": TType, "uuid": TType,
}

// funcs are only functions when a ( follows, so "user" in a sentence is a
// bareword and user() is an evil function.
var funcs = map[string]byte{
	// evil functions (only when followed by a paren, see tokenizer)
	"sleep": TEvilFunc, "benchmark": TEvilFunc, "pg_sleep": TEvilFunc, "xp_cmdshell": TEvilFunc,
	"xp_regread": TEvilFunc, "xp_dirtree": TEvilFunc, "xp_fileexist": TEvilFunc,
	"sp_executesql": TEvilFunc, "sp_oacreate": TEvilFunc, "sp_oamethod": TEvilFunc,
	"sp_password": TEvilFunc, "sp_addextendedproc": TEvilFunc, "openrowset": TEvilFunc,
	"opendatasource": TEvilFunc, "openquery": TEvilFunc, "extractvalue": TEvilFunc,
	"updatexml": TEvilFunc, "utl_http": TEvilFunc, "utl_inaddr": TEvilFunc, "utl_file": TEvilFunc,
	"dbms_pipe": TEvilFunc, "dbms_lock": TEvilFunc, "dbms_xmlgen": TEvilFunc, "ctxsys": TEvilFunc,
	"pg_read_file": TEvilFunc, "pg_ls_dir": TEvilFunc, "copy": TEvilFunc, "lo_import": TEvilFunc,
	"lo_export": TEvilFunc, "randomblob": TEvilFunc, "zeroblob": TEvilFunc, "sqlite_version": TEvilFunc,
	"load_extension": TEvilFunc, "exp": TEvilFunc, "gtid_subset": TEvilFunc, "json_keys": TEvilFunc,
	"polygon": TEvilFunc, "multipoint": TEvilFunc, "linestring": TEvilFunc, "geometrycollection": TEvilFunc,
	"procedure analyse": TEvilFunc, "make_set": TEvilFunc, "elt": TEvilFunc, "current_user": TEvilFunc,
	"system_user": TEvilFunc, "session_user": TEvilFunc, "user": TEvilFunc, "database": TEvilFunc,
	"schema": TEvilFunc, "version": TEvilFunc, "xp_makecab": TEvilFunc,
	"xp_ntsec_enumdomains": TEvilFunc, "xp_terminate_process": TEvilFunc, "xp_loginconfig": TEvilFunc,
	"xp_availablemedia": TEvilFunc, "xp_enumdsn": TEvilFunc, "xp_servicecontrol": TEvilFunc,
	"sys_eval": TEvilFunc, "sys_exec": TEvilFunc, "dbms_java": TEvilFunc, "dbms_scheduler": TEvilFunc,

	// ordinary functions
	"concat": TFunc, "concat_ws": TFunc, "group_concat": TFunc, "substring": TFunc, "substr": TFunc,
	"mid": TFunc, "left": TFunc, "right": TFunc, "ascii": TFunc, "chr": TFunc, "char": TFunc,
	"ord": TFunc, "hex": TFunc, "unhex": TFunc, "length": TFunc, "char_length": TFunc,
	"lower": TFunc, "upper": TFunc, "lcase": TFunc, "ucase": TFunc, "count": TFunc, "sum": TFunc,
	"min": TFunc, "max": TFunc, "avg": TFunc, "cast": TFunc, "convert": TFunc, "coalesce": TFunc,
	"ifnull": TFunc, "nullif": TFunc, "isnull": TFunc, "if": TFunc, "iif": TFunc, "floor": TFunc,
	"rand": TFunc, "round": TFunc, "md5": TFunc, "sha1": TFunc, "sha2": TFunc, "now": TFunc,
	"curdate": TFunc, "sysdate": TFunc, "getdate": TFunc, "replace": TFunc, "reverse": TFunc,
	"repeat": TFunc, "space": TFunc, "strcmp": TFunc, "instr": TFunc, "locate": TFunc,
	"position": TFunc, "trim": TFunc, "ltrim": TFunc, "rtrim": TFunc, "lpad": TFunc, "rpad": TFunc,
	"bin": TFunc, "oct": TFunc, "conv": TFunc, "abs": TFunc, "ceil": TFunc, "ceiling": TFunc,
	"pow": TFunc, "power": TFunc, "sqrt": TFunc, "mod": TFunc, "greatest": TFunc, "least": TFunc,
	"row_count": TFunc, "found_rows": TFunc, "last_insert_id": TFunc, "connection_id": TFunc,
	"quote": TFunc, "format": TFunc, "encode": TFunc, "decode": TFunc, "compress": TFunc,
	"uncompress": TFunc, "aes_encrypt": TFunc, "aes_decrypt": TFunc, "des_encrypt": TFunc,
	"generate_series": TFunc, "array_agg": TFunc, "string_agg": TFunc, "regexp_replace": TFunc,
	"to_char": TFunc, "to_number": TFunc, "to_date": TFunc, "nvl": TFunc, "decode_oracle": TFunc,
	"sysdate_oracle": TFunc, "dbms_output": TFunc,
	"json_extract": TFunc, "json_value": TFunc, "json_query": TFunc, "xmltype": TFunc,
	"char_": TFunc, "nchar_": TFunc, "unicode": TFunc, "soundex": TFunc, "difference": TFunc,
	"stuff": TFunc, "patindex": TFunc, "charindex": TFunc, "datalength": TFunc, "len": TFunc,
	"quotename": TFunc, "str": TFunc, "ntile": TFunc, "row_number": TFunc, "rank": TFunc,
	"dense_rank": TFunc, "lag": TFunc, "lead": TFunc, "first_value": TFunc, "last_value": TFunc,
}

// lookup is case-insensitive without allocating for the common ascii case.
func lookup(word []byte) (byte, bool) {
	var buf [64]byte
	if len(word) > len(buf) {
		return 0, false
	}
	n := 0
	for _, c := range word {
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		buf[n] = c
		n++
	}
	t, ok := keywords[string(buf[:n])]
	return t, ok
}

func lookupPair(a, b []byte) (byte, bool) {
	if len(a)+len(b) > 40 {
		return 0, false
	}
	s := strings.ToLower(string(a)) + " " + strings.ToLower(string(b))
	t, ok := keywords[s]
	return t, ok
}

func isStrong(word []byte) bool {
	return strongKeyword[strings.ToLower(string(word))]
}

func lookupFunc(word []byte) (byte, bool) {
	var buf [64]byte
	if len(word) > len(buf) {
		return 0, false
	}
	n := 0
	for _, c := range word {
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		buf[n] = c
		n++
	}
	t, ok := funcs[string(buf[:n])]
	return t, ok
}
