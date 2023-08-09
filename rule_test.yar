import "pe"

rule DebuggerException__SetConsoleCtrl : AntiDebug DebuggerException {
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
	strings:
		$ ="SetConsoleCtrlHandler"
	condition:
		any of them
}

rule Str_Win32_Http_API
{
    meta:
        author = "@adricnet"
        description = "Match Windows Http API call"
        method = "String match, trim the As"
        reference = "https://github.com/dfirnotes/rules"

    strings:
        $wininet_call_httpr = "HttpSendRequest"
        $wininet_call_httpq = "HttpQueryInfo"
        $wininet_call_httpo = "HttpOpenRequest"

     condition:
        (any of ($wininet_call_http*))
}