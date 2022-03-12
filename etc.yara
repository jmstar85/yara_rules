import "pe"
import "hash"
import "math"


rule CISA_10257062_01 : ATM_Malware
{
   meta:
       Author = "CISA Code & Media Analysis"
       Incident = "10257062"
       Date = "2019-09-26"
       Last_Modified = "20200117_1732"
       Actor = "n/a"
       Category = "Financial"
       Family = "ATM_Malware"
       Description = "n/a"
       MD5_1 = "c4141ee8e9594511f528862519480d36"
       SHA256_1 = "129b8825eaf61dcc2321aad7b84632233fa4bbc7e24bdf123b507157353930f0"
   strings:
       $x3 = "RECV SOCK= 0x%p, BUF= 0x%p, LEN= 0x%08X, RET= %08X, IP= %s, Port= %d" fullword ascii
       $x4 = "init_hashmap succ" fullword ascii
       $x5 = "89*(w8y92r3y9*yI2H28Y9(*y3@*" fullword ascii
   condition:
       ($x3) and ($x4) and ($x5)
}

rule CISA_10292089_01 : rat loader TAIDOOR
{
   meta:
       Author = "CISA Code & Media Analysis"
       Incident = "10292089"
       Date = "2020-06-18"    
       Last_Modified = "20200616_1530"
       Actor = "n/a"
       Category = "Trojan Loader Rat"
       Family = "TAIDOOR"
       Description = "Detects Taidoor Rat Loader samples"
       MD5_1 = "8cf683b7d181591b91e145985f32664c"
       SHA256_1 = "363ea096a3f6d06d56dc97ff1618607d462f366139df70c88310bbf77b9f9f90"
       MD5_2 = "6627918d989bd7d15ef0724362b67edd"
       SHA256_2 = "0d0ccfe7cd476e2e2498b854cef2e6f959df817e52924b3a8bcdae7a8faaa686"
   strings:
       $s0 = { 8A 46 01 88 86 00 01 00 00 8A 46 03 88 86 01 01 00 00 8A 46 05 88 86 02 01 00 00 8A 46 07 88 86 03 01 00 00 }
       $s1 = { 88 04 30 40 3D 00 01 00 00 7C F5 }
       $s2 = { 0F BE 04 31 0F BE 4C 31 01 2B C3 2B CB C1 E0 04 0B C1 }
       $s3 = { 8A 43 01 48 8B 6C 24 60 88 83 00 01 00 00 8A 43 03 }
       $s4 = { 88 83 01 01 00 00 8A 43 05 88 83 02 01 00 00 8A 43 07 88 83 03 01 00 00 }
       $s5 = { 41 0F BE 14 7C 83 C2 80 41 0F BE 44 7C 01 83 C0 80 C1 E2 04 0B D0 }
       $s6 = { 5A 05 B2 CB E7 45 9D C2 1D 60 F0 4C 04 01 43 85 3B F9 8B 7E }
   condition:
       ($s0 and $s1 and $s2) or ($s3 and $s4 and $s5) or ($s6)
}

rule CISA_10296782_01 : trojan WELLMESS
{
meta:
    Author = "CISA Code & Media Analysis"
    Date= "2020-07-06"
    Last_Modified="20200706_1017"
    Actor="n/a"
    Category="Trojan"
    Family="WellMess"
    Description = "Detects WellMess implant and SangFor Exploit"
    MD5_1 = "4d38ac3319b167f6c8acb16b70297111"
    SHA256_1 = "7c39841ba409bce4c2c35437ecf043f22910984325c70b9530edf15d826147ee"
    MD5_2 = "a32e1202257a2945bf0f878c58490af8"
    SHA256_2 = "a4b790ddffb3d2e6691dcacae08fb0bfa1ae56b6c73d70688b097ffa831af064"
    MD5_3 = "861879f402fe3080ab058c0c88536be4"
    SHA256_3 = "14e9b5e214572cb13ff87727d680633f5ee238259043357c94302654c546cad2"
    MD5_4 = "2f9f4f2a9d438cdc944f79bdf44a18f8"
    SHA256_4 = "e329607379a01483fc914a47c0062d5a3a8d8d65f777fbad2c5a841a90a0af09"
    MD5_5 = "ae7a46529a0f74fb83beeb1ab2c68c5c"
    SHA256_5 = "fd3969d32398bbe3709e9da5f8326935dde664bbc36753bd41a0b111712c0950"
    MD5_6 = "f18ced8772e9d1a640b8b4a731dfb6e0"
    SHA256_6 = "953b5fc9977e2d50f3f72c6ce85e89428937117830c0ed67d468e2d93aa7ec9a"
    MD5_7 = "3a9cdd8a5cbc3ab10ad64c4bb641b41f"
    SHA256_7 = "5ca4a9f6553fea64ad2c724bf71d0fac2b372f9e7ce2200814c98aac647172fb"
    MD5_8 = "967fcf185634def5177f74b0f703bdc0"
    SHA256_8 = "58d8e65976b53b77645c248bfa18c3b87a6ecfb02f306fe6ba4944db96a5ede2"
    MD5_9 = "c5d5cb99291fa4b2a68b5ea3ff9d9f9a"
    SHA256_9 = "65495d173e305625696051944a36a031ea94bb3a4f13034d8be740982bc4ab75"
    MD5_10 = "01d322dcac438d2bb6bce2bae8d613cb"
    SHA256_10 = "0c5ad1e8fe43583e279201cdb1046aea742bae59685e6da24e963a41df987494"
    MD5_11 = "8777a9796565effa01b03cf1cea9d24d"
    SHA256_11 = "83014ab5b3f63b0253cdab6d715f5988ac9014570fa4ab2b267c7cf9ba237d18"
    MD5_12 = "507bb551bd7073f846760d8b357b7aa9"
    SHA256_12 = "47cdb87c27c4e30ea3e2de620bed380d5aed591bc50c49b55fd43e106f294854"
strings:
    $0 = "/home/ubuntu/GoProject/src/bot/botlib/chat.go"
    $1 = "/home/ubuntu/GoProject/src/bot/botlib.Post"
    $2 = "GoProject/src/bot/botlib.deleteFile"
    $3 = "ubuntu/GoProject/src/bot/botlib.generateRandomString"
    $4 = "GoProject/src/bot/botlib.AES_Decrypt"
    $5 = { 53 00 63 00 72 00 69 00 70 00 74 00 00 0F 63 00 6D 00 64 00 2E 00 65 00 78 00 65 00 00 07 2F 00 63 }
    $6 = { 3C 00 6E 00 77 00 3E 00 2E 00 2A 00 29 00 00 0B 24 00 7B 00 66 00 6E 00 7D }
    $7 = { 7B 00 61 00 72 00 67 00 7D 00 00 0B 24 00 7B 00 6E 00 77 00 7D }
    $8 = { 52 61 6E 64 6F 6D 53 74 72 69 6E 67 00 44 65 6C 65 74 65 46 69 6C 65 }
    $9 = "get_keyRC6"
    $10 = { 7D A3 26 77 1D 63 3D 5A 32 B4 6F 1F 55 49 44 25 }
    $11 = { 47 C2 2F 35 93 41 2F 55 73 0B C2 60 AB E1 2B 42 }
    $12 = { 53 58 9B 17 1F 45 BD 72 EC 01 30 6C 4F CA 93 1D }
    $13 = { 48 81 21 81 5F 53 3A 64 E0 ED FF 21 23 E5 00 12 }
    $14 = "GoProject/src/bot/botlib.wellMess"
    $15 = { 62 6F 74 6C 69 62 2E 4A 6F 69 6E 44 6E 73 43 68 75 6E 6B 73 }
    $16 = { 62 6F 74 6C 69 62 2E 45 78 65 63 }
    $17 = { 62 6F 74 6C 69 62 2E 47 65 74 52 61 6E 64 6F 6D 42 79 74 65 73 }
    $18 = { 62 6F 74 6C 69 62 2E 4B 65 79 }
    $19 = { 7F 16 21 9D 7B 03 CB D9 17 3B 9F 27 B3 DC 88 0F }
    $20 = { D9 BD 0A 0E 90 10 B1 39 D0 C8 56 58 69 74 15 8B }
    $21 = { 44 00 59 00 4A 00 20 00 36 00 47 00 73 00 62 00 59 00 31 00 2E }
    $22 = { 6E 00 20 00 46 00 75 00 7A 00 2C 00 4B 00 5A 00 20 00 33 00 31 00 69 00 6A 00 75 }
    $23 = { 43 00 31 00 69 00 76 00 66 00 39 00 32 00 20 00 56 00 37 00 6C 00 4F 00 48 }
    $24 = { 66 69 6C 65 4E 61 6D 65 3A 28 3F 50 3C 66 6E 3E 2E 2A 3F 29 5C 73 61 72 67 73 3A 28 3F 50 3C 61 72 67 3E 2E 2A 3F }
    $25 = { 5C 00 2E 00 53 00 61 00 6E 00 67 00 66 00 6F 00 72 00 55 00 44 00 2E 00 73 00 75 00 6D }
    $26 = { 66 6F 72 6D 2D 64 61 74 61 3B 20 6E 61 6D 65 3D 22 5F 67 61 22 3B 20 66 69 6C 65 6E 61 6D 65 3D }
    $27 = { 40 5B 5E 5C 73 5D 2B 3F 5C 73 28 3F 50 3C 74 61 72 3E 2E 2A 3F 29 5C 73 27 }
condition:
   ($0 and $1 and $2 and $3 and $4) or ($5 and $6 and $7 and $8 and $9) or ($10 and $11) or ($12 and $13) or ($14) or ($15 and $16 and $17 and $18) or ($19 and $20) or ($21 and $22 and $23) or ($24) or ($25 and $26) or ($27)
}


rule CISA_import_obfuscation_2 
{ 
   meta: 
      author = "NCCIC trusted 3rd party" 
      incident = "10135536" 
      date = "2018-04-12" 
      category = "hidden_cobra" 
      family = "TYPEFRAME" 
      hash0 = "bfb41bc0c3856aa0a81a5256b7b8da51" 
   strings: 
      $s0 = {A6 D6 02 EB 4E B2 41 EB C3 EF 1F} 
      $s1 = {B6 DF 01 FD 48 B5 } 
      $s2 = {B6 D5 0E F3 4E B5 } 
      $s3 = {B7 DF 0E EE } 
      $s4 = {B6 DF 03 FC } 
      $s5 = {A7 D3 03 FC } 
   condition: (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) and all of them 
}

rule tool_3proxy_strings {
    meta:
        description = "3Proxy tiny proxy server"
        author = "JPCERT/CC Incident Response Group"
        reference = "http://3proxy.ru/"
     strings:
        $str1 = "http://3proxy.ru/" ascii
        $str2 = "size of network buffer (default 4096 for TCP, 16384 for UDP)" ascii
        $str3 = "value to add to default client thread stack size" ascii
        $str4 = "Connect back not received, check connback client" ascii
        $str5 = "Failed to allocate connect back socket" ascii
        $str6 = "Warning: too many connected clients (%d/%d)" ascii
     condition:
        3 of ($str*)
}

rule webshell_adminer_4_7 {
     meta:
        description = "Webshell Adminer4.7"
        author = "JPCERT/CC Incident Response Group"
        hash = "7897ac51d8e50c550acae4204d0139cb2a5d0b6c11ca506978b237f8fe540fd1"

     strings:
        $str1 = "bruteForceKey()"
        $str2 = "https://www.adminer.org/"
        $str3 = "$_COOKIE[\"adminer_permanent\"]"
        $str4 = "process_list()"
        $str5 = "routine_languages()"
        $str6 = "$_COOKIE[\"adminer_key\"]"
        $str7 = "lzw_decompress($"
        $str8 = "preg_match('~^(database|table|columns|sql|indexes|"

     condition:
       uint32(0) == 0x68703F3C and 5 of ($str*)
}

rule malware_Agenttesla_type1 {
          meta:
            description = "detect Agenttesla in memory"
            author = "JPCERT/CC Incident Response Group"
            rule_usage = "memory scan"
            reference = "internal research"

          strings:
            $iestr = "C:\\\\Users\\\\Admin\\\\Desktop\\\\IELibrary\\\\IELibrary\\\\obj\\\\Debug\\\\IELibrary.pdb"
            $atstr = "C:\\\\Users\\\\Admin\\\\Desktop\\\\ConsoleApp1\\\\ConsoleApp1\\\\obj\\\\Debug\\\\ConsoleApp1.pdb"
            $sqlitestr = "Not a valid SQLite 3 Database File" wide

          condition:
            all of them
}

rule malware_Agenttesla_type2 {
          meta:
            description = "detect Agenttesla in memory"
            author = "JPCERT/CC Incident Response Group"
            rule_usage = "memory scan"
            reference = "internal research"
            hash1 = "670a00c65eb6f7c48c1e961068a1cb7fd3653bd29377161cd04bf15c9d010da2 "

          strings:
            $type2db1 = "1.85 (Hash, version 2, native byte-order)" wide
            $type2db2 = "Unknow database format" wide
            $type2db3 = "SQLite format 3" wide
            $type2db4 = "Berkelet DB" wide

          condition:
            (uint16(0) == 0x5A4D) and 3 of them
}

rule malware_Ares_str {
     meta:
        description = "Ares Python based remote access tool"
        author = "JPCERT/CC Incident Response Group"
        hash = "52550953e6bc748dc4d774fbea66382cc2979580173a7388c01589e8cb882659"
        hash = "123d7abb725bba4e5f9af2f46ff2200d802896fc7b7102c59b1c3a996c48e1b6"
        hash = "f13c5b383710e58dcf6f4a92ed535cc824a77964bdfa358b017aa3dd75e8cb13"

     strings:
        $data1 = "Agent removed successfully" ascii wide
        $data2 = "starting server_hello" ascii wide
        $data3 = "Running python command..." ascii wide
        $data4 = "Creating zip archive..." ascii wide
        $data5 = "Running python file..." ascii wide
        $data6 = "Archive created: %s" ascii wide
        $data7 = "Exiting... (bye!)" ascii wide
        $data8 = "update_consecutive_failed_connections" ascii wide
        $data9 = "get_consecutive_failed_connections" ascii wide
        $data10 = "~/.config/autostart/ares.desktop" ascii wide
        $data11 = "get_install_dir" ascii wide
        $data12 = "command_or_file" ascii wide

     condition:
       5 of ($data*)
}

rule malware_asyncrat {
    meta:
        description = "detect AsyncRat in memory"
        author = "JPCERT/CC Incident Response Group"
        rule_usage = "memory scan"
        reference = "internal research"
        hash1 = "1167207bfa1fed44e120dc2c298bd25b7137563fdc9853e8403027b645e52c19"
        hash2 = "588c77a3907163c3c6de0e59f4805df41001098a428c226f102ed3b74b14b3cc"

    strings:
        $salt = {BF EB 1E 56 FB CD 97 3B B2 19 02 24 30 A5 78 43 00 3D 56 44 D2 1E 62 B9 D4 F1 80 E7 E6 C3 39 41}
        $b1 = {00 00 00 0D 53 00 48 00 41 00 32 00 35 00 36 00 00}
        $b2 = {09 50 00 6F 00 6E 00 67 00 00}
        $s1 = "pastebin" ascii wide nocase
        $s2 = "pong" wide
        $s3 = "Stub.exe" ascii wide

    condition:
        ($salt and (2 of ($s*) or 1 of ($b*))) or (all of ($b*) and 2 of ($s*))
}

rule malware_Azorult {
          meta:
            description = "detect Azorult in memory"
            author = "JPCERT/CC Incident Response Group"
            rule_usage = "memory scan"
            reference = "internal research"

          strings:
            $v1 = "Mozilla/4.0 (compatible; MSIE 6.0b; Windows NT 5.1)"
            $v2 = "http://ip-api.com/json"
            $v3 = { c6 07 1e c6 47 01 15 c6 47 02 34 }

          condition:
            all of them
}

rule webshell_b374k_str {
     meta:
        description = "Webshell b374k"
        author = "JPCERT/CC Incident Response Group"
        hash = "8c30f0ad13f188cb24481bc28512e8f71fd4188d6c6020cfe0c26f43a8233d91"

     strings:
        $b374k2_1 = "$_COOKIE['b374k']"
        $b374k2_2 = "CrOq1gLF3fYNrLiX+Bs8MoTwT2fQPwXgBXHGL+TaIjfinb3C7cscRMIcYL6AAAAAElFTkSuQmCC"
        $b374k2_3 = "J+CS0xFMxf8Ks6rWAsXd9g2suJf4GzwyhPBPZ9A/BeAFccYv5NoiN+KdvcLtyxxEwhxgvoAAAAASUVORK5CYII="
        $b374k2_4 = "<input class='inputzbut' type='submit' value='Go !' name='submitlogin' style='width:80px;' />"
        $b374k3_1 = "TYvfFXKszKl7t7TkzpzJO8l6zI9ki1soLaypb96wl3/cBydJKPVPWP/wI="
        $b374k3_2 = "atN9HV7ZsuZFAIRngh0oVQKZXb+fgBOdQNKnDsVQvjnz/8="
        $b374kencode = "func=\"cr\".\"eat\".\"e_fun\".\"cti\".\"on\";$b374k="

     condition:
       3 of ($b374k2_*) or all of ($b374k3_*) or $b374kencode
}

rule malware_Bebloh_strings {
          meta:
            description = "detect Bebloh(a.k.a. URLZone) in memory"
            author = "JPCERT/CC Incident Response Group"
            rule_usage = "memory scan"
            reference = "internal research"

          strings:
            $crc32f = { b8 EE 56 0b ca }
            $dga = "qwertyuiopasdfghjklzxcvbnm123945678"
            $post1 = "&vcmd="
            $post2 = "?tver="

          condition:
            all of them
}

rule malware_CobaltStrike_v3v4 {
          meta:
            description = "detect CobaltStrike Beacon in memory"
            author = "JPCERT/CC Incident Response Group"
            rule_usage = "memory scan"
            reference = "https://blogs.jpcert.or.jp/en/2018/08/volatility-plugin-for-detecting-cobalt-strike-beacon.html"
            hash1 = "154db8746a9d0244146648006cc94f120390587e02677b97f044c25870d512c3"
            hash2 = "f9b93c92ed50743cd004532ab379e3135197b6fb5341322975f4d7a98a0fcde7"

          strings:
            $v1 = { 73 70 72 6E 67 00 }
            $config3 = { 69 69 69 69 69 69 69 69 }
            $config4 = { 2E 2E 2E 2E 2E 2E 2E 2E }

          condition:
            $v1 and 1 of ($config*)
}

rule malware_CobaltStrike_beacon {
     meta:
        description = "CobaltStrike encoding code"
        author = "JPCERT/CC Incident Response Group"
        hash = "1957d8e71c1b14be9b9bde928b47629d8283b8165015647b429f83d11a0d6fb3"
        hash = "4b2b14c79d6476af373f319548ac9e98df3be14319850bec3856ced9a7804237"

     strings:
        $code1 = { 5? 8B ?? 83 C? 04 8B ?? 31 ?? 83 C? 04 5? 8B ?? 31 ?? 89 ?? 31 ?? 83 C? 04 83 E? 04 31 ?? 39 ?? 74 02 EB E? 5? FF E? E8 ?? FF FF FF }
        $code2 = { 5D 8B ?? 00 83 C? 04 8B ?? 00 31 ?? 83 C? 04 5? 8B ?? 00 31 ?? 89 ?? 00 31 ?? 83 C? 04 83 E? 04 31 ?? 39 ?? 74 02 EB E? 5? FF E? E8 ?? FF FF FF }

     condition:
        uint16(0) == 0xE8FC and
        $code1 in (6..200) or $code2 in (6..200)
}

rule CryptHunter_downloaderjs {
     meta:
        description = "JS downloader executed from an lnk file used in CryptHunter"
        author = "JPCERT/CC Incident Response Group"
        hash = "bb7349d4fd7efa838a92fc4a97ec2a25b82dde36236bdc09b531c20370d7f848"

     strings:
        $a = "pi.ProcessID!==0 && pi.ProcessID!==4){"
        $b = "prs=prs+pi.CommandLine.toLowerCase();}"

     condition:
       any of them
}

rule CryptHunter_lnk_bitly {
      meta:
        description = "detect suspicious lnk file"
        author = "JPCERT/CC Incident Response Group"
        reference = "internal research"
        hash1 = "01b5cd525d18e28177924d8a7805c2010de6842b8ef430f29ed32b3e5d7d99a0"

      strings:
        $a1 = "cmd.exe" wide ascii
        $a2 = "mshta" wide ascii
        $url1 = "https://bit.ly" wide ascii

      condition:
        (uint16(0) == 0x004c) and
        (filesize<100KB)  and
        ((1 of ($a*)) and ($url1))
}

rule CryptHunter_httpbotjs_str {
    meta:
        description = "HTTP bot js in CryptHunter"
        author = "JPCERT/CC Incident Response Group"
        hash1 = "b316b81bc0b0deb81da5e218b85ca83d7260cc40dae97766bc94a6931707dc1b"

     strings:
        $base64 = "W0NtZGxldEJpbmRpbmcoKV1QYXJhbShbUGFyYW1ldGVyKFBvc2l0aW9uPTApXVtTdHJpbmddJFVSTCxbUGFyYW1ldGVyKFBvc2l0aW9uPTEpXVtTdHJpbmddJFVJRCkNCmZ1bmN0aW9uIEh0dHBSZXEyew" ascii
        $var1 = { 40 28 27 22 2b 70 32 61 2b 22 27 2c 20 27 22 2b 75 69 64 2b 22 27 29 3b 7d }

     condition:
        all of them
}

rule cve202120837_webshell_fox {
     meta:
        description = "CVE-2021-20837 PHP webshell (fox)"
        author = "JPCERT/CC Incident Response Group"
        hash = "654c4a51f8caa0535b04c692114f2f096a4b6b87bd6f9e1bcce216a2158b518d"

     strings:
        $encode1 = "eval(str_rot13(gzinflate(str_rot13(base64_decode("
        $encode2 = "6576616C28677A756E636F6D7072657373286261736536345F6465636F64652827"
        $str1 = "deleteDir("
        $str2 = "http_get_contents1("
        $str3 = "http_get_contents2("
        $str4 = "httpsCurl("

     condition:
        uint32(0) == 0x68703F3C and (1 of ($encode*) or all of ($str*))
}

rule cve202120837_webshell_HelloDolly {
     meta:
        description = "CVE-2021-20837 PHP webshell (fake Hello Dolly)"
        author = "JPCERT/CC Incident Response Group"
        hash = "776264178e8534b6404e649e0256e5467639b14e2bf2c778c6b25dc944dee211"

     strings:
        $str1 = "data:image/png;ZXJyb3JfcmVwb3J0a"
        $str2 = "\\x63\\x72\\x65\\x61\\x74\\x65\\x5f\\x66\\x75\\x6e\\x63\\x74\\x69\\x6f\\x6e"  // create_function
        $str3 = { 3C 46 69 6C 65 73 4D 61 74 63 68 20 5C 22 2E 28 70 68 7C 70 68 74 6D 6C 7C 70 68 70 29 5C 24 5C 22 3E 5C 6E 20 4F 72 64 65 72 20 61 6C 6C 6F 77 2C 64 65 6E 79 5C 6E 20 41 6C 6C 6F 77 20 66 72 6F 6D 20 61 6C 6C 5C 6E 3C 2F 46 69 6C 65 73 4D 61 74 63 68 3E } // <FilesMatch \".(ph|phtml|php)\$\">\n Order allow,deny\n Allow from all\n</FilesMatch>
        $str4 = { 23 3C 69 6D 67 20 73 72 63 3D 22 64 61 74 61 3A 69 6D 61 67 65 2F 70 6E 67 3B 28 2E 2A 29 22 3E 23 } // #<img src="data:image/png;(.*)">#

     condition:
        uint32(0) == 0x68703F3C and 2 of ($str*)
}

rule malware_Doraemon {
    meta:
      description = "detect Doraemon Earth Lusca"
      author = "JPCERT/CC Incident Response Group"
      hash1 = "2d3699607194d1a2a6c1eeeb5d0e5e5e385b78d94d5053e38e3c1908c5ced1c6"
      hash2 = "95aa15baeef978b99e63a406fa06a1197f6f762047f9729f17bb49b72ead6477"
	  
    strings:
      /* Mutex */
      $mut1 = {?? ?? ?? ?? 64 00 6F 00 ?? ?? ?? ?? 72 00 61 00 ?? ?? ?? ?? 65 00 6D 00 ?? ?? ?? ?? 6F 00 6E 00}

      /* xor */
      $xorfunc = {42 8B 04 02 4D 8D 40 04 41 31 40 FC}

      /* const num */
      $doubleNum1 = {9A 99 99 99 99 99 F1 3F}
	  
      /* strings */
      $str1 = "Doraemon.dll" fullword ascii
      $api1 = "BitBlt" fullword ascii
      $api2 = "EncodePointer" fullword ascii
      $api3 = "ReadConsoleW" fullword ascii

    condition:
	  (uint16(0) == 0x5A4D)
	  and (filesize < 1MB)
	  and (2 of ($api*))
	  and all of them
}

rule malware_Emotet {
          meta:
            description = "detect Emotet in memory"
            author = "JPCERT/CC Incident Response Group"
            rule_usage = "memory scan"
            reference = "internal research"

          strings:
            $v4a = { BB 00 C3 4C 84 }
            $v4b = { B8 00 C3 CC 84 }
            $v5a = { 6D 4E C6 41 33 D2 81 C1 39 30 00 00 }
            $v6a = { C7 40 20 ?? ?? ?? 00 C7 40 10 ?? ?? ?? 00 C7 40 0C 00 00 00 00 83 3C CD ?? ?? ?? ?? 00 74 0E 41 89 48 ?? 83 3C CD ?? ?? ?? ?? 00 75 F2 }
            $v7a = { 6A 06 33 D2 ?? F7 ?? 8B DA 43 74 }
            $v7b = { 83 E6 0F 8B CF 83 C6 04 50 8B D6 E8 ?? ?? ?? ?? 59 6A 2F 8D 3C 77 58 66 89 07 83 C7 02 4B 75 }

          condition:
          all of ($v4*) or $v5a or $v6a or all of ($v7*)
}

rule webshell_filesman_base64 {
     meta:
        description = "Webshell FilesMan"
        author = "JPCERT/CC Incident Response Group"
        hash = "01bd043b401144d60f09758eea5f2d13284f4fb682f8f99de032a84c4a0b6fe5"

     strings:
        $str1 = "IyEvdXNyL2Jpbi9wZXJsDQp1c2UgU29ja2V0Ow0KJGlhZGRyPWluZXRfYXRvbigkQVJHVlswXSkgfHwgZGllKCJFcnJvcjogJCFcbiIpOw0KJHBhZGRyPXNvY2thZGRy"
        $str2 = "IyEvdXNyL2Jpbi9wZXJsDQokU0hFTEw9Ii9iaW4vc2ggLWkiOw0KaWYgKEBBUkdWIDwgMSkgeyBleGl0KDEpOyB9DQp1c2UgU29ja2V0Ow0Kc29ja2V0KFMsJlBGX0"

     condition:
       uint32(0) == 0x68703F3C and all of them
}

rule webshell_phpencode_base64 {
     meta:
        description = "Multiple base64 encoded php code"
        author = "JPCERT/CC Incident Response Group"
        hash = "b0fb71780645bacb0f9cae41310a43ef4fa3548961ca4b2adb23464ad9ec2f10"

     strings:
        $str1 = "KSkpKSkpKSkpKSkpOw=='));"
        $str2 = "eval(base64_decode('ZnVuY3Rpb24gX"

     condition:
       uint32(0) == 0x68703F3C and all of them
}

rule malware_flubot_webshell {
     meta:
        description = "Webshell used in FluBot download page"
        author = "JPCERT/CC Incident Response Group"
        hash = "18f154adc2a1267b67d05ea125a3b1991c28651c638f0a00913d601c6237c2bc"

     strings:
        $token   = "aG1mN2ZkcXM5dmZ4cDhzNHJ3cXp4YmZ6NmM0M2J3Z2I="  // hmf7fdqs9vfxp8s4rwqzxbfz6c43bwgb
        $param01 = "Zm9yY2VfcmVkaXJlY3Rfb2ZmZXI="                  // force_redirect_offer
        $param02 = "c3ViX2lkXz"                                    // sub_id_
        $message01 = "RFctVkFMSUQtT0s="                            // DW-VALID-OK
        $message02 = "RFctSU5WQUxJRC1F"                            // DW-INVALID-E
        $message03 = "S1QtVkFMSUQtT0s="                            // KT-VALID-OK
        $message04 = "S1QtSU5WQUxJRC1F"                            // KT-INVALID-E

     condition:
       all of ($message*) or all of ($param*) or $token
}

rule malware_Formbook_strings {
          meta:
            description = "detect Formbook in memory"
            author = "JPCERT/CC Incident Response Group"
            rule_usage = "memory scan"
            reference = "internal research"

          strings:
            $sqlite3step = { 68 34 1c 7b e1 }
            $sqlite3text = { 68 38 2a 90 c5 }
            $sqlite3blob = { 68 53 d8 7f 8c }

          condition:
            all of them
}

rule webshell_FoxWSO_str {
     meta:
        description = "Webshell FoxWSO"
        author = "JPCERT/CC Incident Response Group"
        hash = "5ab2258d38805007226166f946bcc2794310bd9889f03fcb1894f2061716b0f9"

     strings:
        $str1 = "tjwlltii akhmhcij"
        $str2 = "!defined('lmhelqpg')"
        $str3 = { 69 66 28 21 66 75 6e 63 74 69 6f 6e 5f 65 78 69 73 74 73 28 22 94 e3 d7 a9 a7 9a e0 c5 f3 f6 22 29 }

     condition:
        uint32(0) == 0x68703F3C and 1 of ($str*)
}

rule malware_Hawkeye_strings {
          meta:
            description = "detect HawkEye in memory"
            author = "JPCERT/CC Incident Response Group"
            rule_usage = "memory scan"
            reference = "internal research"

          strings:
            $hawkstr1 = "HawkEye Keylogger" wide
            $hawkstr2 = "Dear HawkEye Customers!" wide
            $hawkstr3 = "HawkEye Logger Details:" wide

          condition:
            all of them
}

rule malware_INetGet_exe
{
  meta:
    description = "APT Malware using INetGet"
    author = "JPCERT/CC Incident Response Group"
    hash = "d3f0af5ab7778846d0eafa4c466c11f11e4ee3b0dc359f732ba588c5a482dbf2"

	strings:
		$v1c = "cookie:flag=" wide
		$v1d = "LoRd_MuldeR" wide
		$w1a = "INetGet.exe" wide

	condition:
		all of them
}

rule malware_INetGet_rtf
{
  meta:
    description = "APT Malware using INetGet"
    author = "JPCERT/CC Incident Response Group"
    hash = "4b366ea3c86fbf8846fa96381d2d267901af436441594a009b76d133a70404f1"

	strings:
		$v1c = "7a337d33563347337433563347331d3356334b3356"
		$v1d = {7B 5C 72 74 5C 61 6E 73 69}

	condition:
		all of them
}

rule malware_lodeinfo_pdb {
    meta:
        description = "LODEINFO malware"
        author = "JPCERT/CC Incident Response Group"
        hash1 = "b50d83820a5704522fee59164d7bc69bea5c834ebd9be7fd8ad35b040910807f"
        hash2 = "d1ed97ebeba07120ffaeef5e19f13d027ef4f4a3f45135f63b6715388b3cf49e"
     strings:
		$pdb1 = "E:\\Production\\Tool-Developing\\"
        $pdb2 = "E:\\Production\\Tool-Developing\\png_info\\Release\\png_info.pdb"
        $func1 = "displayAsciiArt"
        $func2 = "displayChunkNames"
        $func3 = "displayFilterTypes"
        $func4 = "displayPNGInfo"
        $func5 = "get_shellcode"
        $docCMG = "BBB975150319031903190319"
     condition:
        (all of ($pdb*) or all of ($func*)) and uint16(0) == 0x5A4D or $docCMG
}


rule malware_lodeinfo_c2_cmd_xor_bruteforce
{
  meta:
    description = "Rule to detect xored command in LODEINFO"
    author = "JPCERT/CC Incident Response Group"
    hash = "3fda6fd600b4892bda1d28c1835811a139615db41c99a37747954dcccaebff6e"

  strings:
    $xor_01 = { 72 64 6f 65 [3-20] 73 64 62 77 [3-20] 6c 64 6c 6e [3-20] 6a 68 6d 6d }
    $xor_02 = { 71 67 6c 66 [3-20] 70 67 61 74 [3-20] 6f 67 6f 6d [3-20] 69 6b 6e 6e }
    $xor_03 = { 70 66 6d 67 [3-20] 71 66 60 75 [3-20] 6e 66 6e 6c [3-20] 68 6a 6f 6f }
    $xor_04 = { 77 61 6a 60 [3-20] 76 61 67 72 [3-20] 69 61 69 6b [3-20] 6f 6d 68 68 }
    $xor_05 = { 76 60 6b 61 [3-20] 77 60 66 73 [3-20] 68 60 68 6a [3-20] 6e 6c 69 69 }
    $xor_06 = { 75 63 68 62 [3-20] 74 63 65 70 [3-20] 6b 63 6b 69 [3-20] 6d 6f 6a 6a }
    $xor_07 = { 74 62 69 63 [3-20] 75 62 64 71 [3-20] 6a 62 6a 68 [3-20] 6c 6e 6b 6b }
    $xor_08 = { 7b 6d 66 6c [3-20] 7a 6d 6b 7e [3-20] 65 6d 65 67 [3-20] 63 61 64 64 }
    $xor_09 = { 7a 6c 67 6d [3-20] 7b 6c 6a 7f [3-20] 64 6c 64 66 [3-20] 62 60 65 65 }
    $xor_0A = { 79 6f 64 6e [3-20] 78 6f 69 7c [3-20] 67 6f 67 65 [3-20] 61 63 66 66 }
    $xor_0B = { 78 6e 65 6f [3-20] 79 6e 68 7d [3-20] 66 6e 66 64 [3-20] 60 62 67 67 }
    $xor_0C = { 7f 69 62 68 [3-20] 7e 69 6f 7a [3-20] 61 69 61 63 [3-20] 67 65 60 60 }
    $xor_0D = { 7e 68 63 69 [3-20] 7f 68 6e 7b [3-20] 60 68 60 62 [3-20] 66 64 61 61 }
    $xor_0E = { 7d 6b 60 6a [3-20] 7c 6b 6d 78 [3-20] 63 6b 63 61 [3-20] 65 67 62 62 }
    $xor_0F = { 7c 6a 61 6b [3-20] 7d 6a 6c 79 [3-20] 62 6a 62 60 [3-20] 64 66 63 63 }
    $xor_10 = { 63 75 7e 74 [3-20] 62 75 73 66 [3-20] 7d 75 7d 7f [3-20] 7b 79 7c 7c }
    $xor_11 = { 62 74 7f 75 [3-20] 63 74 72 67 [3-20] 7c 74 7c 7e [3-20] 7a 78 7d 7d }
    $xor_12 = { 61 77 7c 76 [3-20] 60 77 71 64 [3-20] 7f 77 7f 7d [3-20] 79 7b 7e 7e }
    $xor_13 = { 60 76 7d 77 [3-20] 61 76 70 65 [3-20] 7e 76 7e 7c [3-20] 78 7a 7f 7f }
    $xor_14 = { 67 71 7a 70 [3-20] 66 71 77 62 [3-20] 79 71 79 7b [3-20] 7f 7d 78 78 }
    $xor_15 = { 66 70 7b 71 [3-20] 67 70 76 63 [3-20] 78 70 78 7a [3-20] 7e 7c 79 79 }
    $xor_16 = { 65 73 78 72 [3-20] 64 73 75 60 [3-20] 7b 73 7b 79 [3-20] 7d 7f 7a 7a }
    $xor_17 = { 64 72 79 73 [3-20] 65 72 74 61 [3-20] 7a 72 7a 78 [3-20] 7c 7e 7b 7b }
    $xor_18 = { 6b 7d 76 7c [3-20] 6a 7d 7b 6e [3-20] 75 7d 75 77 [3-20] 73 71 74 74 }
    $xor_19 = { 6a 7c 77 7d [3-20] 6b 7c 7a 6f [3-20] 74 7c 74 76 [3-20] 72 70 75 75 }
    $xor_1A = { 69 7f 74 7e [3-20] 68 7f 79 6c [3-20] 77 7f 77 75 [3-20] 71 73 76 76 }
    $xor_1B = { 68 7e 75 7f [3-20] 69 7e 78 6d [3-20] 76 7e 76 74 [3-20] 70 72 77 77 }
    $xor_1C = { 6f 79 72 78 [3-20] 6e 79 7f 6a [3-20] 71 79 71 73 [3-20] 77 75 70 70 }
    $xor_1D = { 6e 78 73 79 [3-20] 6f 78 7e 6b [3-20] 70 78 70 72 [3-20] 76 74 71 71 }
    $xor_1E = { 6d 7b 70 7a [3-20] 6c 7b 7d 68 [3-20] 73 7b 73 71 [3-20] 75 77 72 72 }
    $xor_1F = { 6c 7a 71 7b [3-20] 6d 7a 7c 69 [3-20] 72 7a 72 70 [3-20] 74 76 73 73 }
    $xor_20 = { 53 45 4e 44 [3-20] 52 45 43 56 [3-20] 4d 45 4d 4f [3-20] 4b 49 4c 4c }
    $xor_21 = { 52 44 4f 45 [3-20] 53 44 42 57 [3-20] 4c 44 4c 4e [3-20] 4a 48 4d 4d }
    $xor_22 = { 51 47 4c 46 [3-20] 50 47 41 54 [3-20] 4f 47 4f 4d [3-20] 49 4b 4e 4e }
    $xor_23 = { 50 46 4d 47 [3-20] 51 46 40 55 [3-20] 4e 46 4e 4c [3-20] 48 4a 4f 4f }
    $xor_24 = { 57 41 4a 40 [3-20] 56 41 47 52 [3-20] 49 41 49 4b [3-20] 4f 4d 48 48 }
    $xor_25 = { 56 40 4b 41 [3-20] 57 40 46 53 [3-20] 48 40 48 4a [3-20] 4e 4c 49 49 }
    $xor_26 = { 55 43 48 42 [3-20] 54 43 45 50 [3-20] 4b 43 4b 49 [3-20] 4d 4f 4a 4a }
    $xor_27 = { 54 42 49 43 [3-20] 55 42 44 51 [3-20] 4a 42 4a 48 [3-20] 4c 4e 4b 4b }
    $xor_28 = { 5b 4d 46 4c [3-20] 5a 4d 4b 5e [3-20] 45 4d 45 47 [3-20] 43 41 44 44 }
    $xor_29 = { 5a 4c 47 4d [3-20] 5b 4c 4a 5f [3-20] 44 4c 44 46 [3-20] 42 40 45 45 }
    $xor_2A = { 59 4f 44 4e [3-20] 58 4f 49 5c [3-20] 47 4f 47 45 [3-20] 41 43 46 46 }
    $xor_2B = { 58 4e 45 4f [3-20] 59 4e 48 5d [3-20] 46 4e 46 44 [3-20] 40 42 47 47 }
    $xor_2C = { 5f 49 42 48 [3-20] 5e 49 4f 5a [3-20] 41 49 41 43 [3-20] 47 45 40 40 }
    $xor_2D = { 5e 48 43 49 [3-20] 5f 48 4e 5b [3-20] 40 48 40 42 [3-20] 46 44 41 41 }
    $xor_2E = { 5d 4b 40 4a [3-20] 5c 4b 4d 58 [3-20] 43 4b 43 41 [3-20] 45 47 42 42 }
    $xor_2F = { 5c 4a 41 4b [3-20] 5d 4a 4c 59 [3-20] 42 4a 42 40 [3-20] 44 46 43 43 }
    $xor_30 = { 43 55 5e 54 [3-20] 42 55 53 46 [3-20] 5d 55 5d 5f [3-20] 5b 59 5c 5c }
    $xor_31 = { 42 54 5f 55 [3-20] 43 54 52 47 [3-20] 5c 54 5c 5e [3-20] 5a 58 5d 5d }
    $xor_32 = { 41 57 5c 56 [3-20] 40 57 51 44 [3-20] 5f 57 5f 5d [3-20] 59 5b 5e 5e }
    $xor_33 = { 40 56 5d 57 [3-20] 41 56 50 45 [3-20] 5e 56 5e 5c [3-20] 58 5a 5f 5f }
    $xor_34 = { 47 51 5a 50 [3-20] 46 51 57 42 [3-20] 59 51 59 5b [3-20] 5f 5d 58 58 }
    $xor_35 = { 46 50 5b 51 [3-20] 47 50 56 43 [3-20] 58 50 58 5a [3-20] 5e 5c 59 59 }
    $xor_36 = { 45 53 58 52 [3-20] 44 53 55 40 [3-20] 5b 53 5b 59 [3-20] 5d 5f 5a 5a }
    $xor_37 = { 44 52 59 53 [3-20] 45 52 54 41 [3-20] 5a 52 5a 58 [3-20] 5c 5e 5b 5b }
    $xor_38 = { 4b 5d 56 5c [3-20] 4a 5d 5b 4e [3-20] 55 5d 55 57 [3-20] 53 51 54 54 }
    $xor_39 = { 4a 5c 57 5d [3-20] 4b 5c 5a 4f [3-20] 54 5c 54 56 [3-20] 52 50 55 55 }
    $xor_3A = { 49 5f 54 5e [3-20] 48 5f 59 4c [3-20] 57 5f 57 55 [3-20] 51 53 56 56 }
    $xor_3B = { 48 5e 55 5f [3-20] 49 5e 58 4d [3-20] 56 5e 56 54 [3-20] 50 52 57 57 }
    $xor_3C = { 4f 59 52 58 [3-20] 4e 59 5f 4a [3-20] 51 59 51 53 [3-20] 57 55 50 50 }
    $xor_3D = { 4e 58 53 59 [3-20] 4f 58 5e 4b [3-20] 50 58 50 52 [3-20] 56 54 51 51 }
    $xor_3E = { 4d 5b 50 5a [3-20] 4c 5b 5d 48 [3-20] 53 5b 53 51 [3-20] 55 57 52 52 }
    $xor_3F = { 4c 5a 51 5b [3-20] 4d 5a 5c 49 [3-20] 52 5a 52 50 [3-20] 54 56 53 53 }
    $xor_40 = { 33 25 2e 24 [3-20] 32 25 23 36 [3-20] 2d 25 2d 2f [3-20] 2b 29 2c 2c }
    $xor_41 = { 32 24 2f 25 [3-20] 33 24 22 37 [3-20] 2c 24 2c 2e [3-20] 2a 28 2d 2d }
    $xor_42 = { 31 27 2c 26 [3-20] 30 27 21 34 [3-20] 2f 27 2f 2d [3-20] 29 2b 2e 2e }
    $xor_43 = { 30 26 2d 27 [3-20] 31 26 20 35 [3-20] 2e 26 2e 2c [3-20] 28 2a 2f 2f }
    $xor_44 = { 37 21 2a 20 [3-20] 36 21 27 32 [3-20] 29 21 29 2b [3-20] 2f 2d 28 28 }
    $xor_45 = { 36 20 2b 21 [3-20] 37 20 26 33 [3-20] 28 20 28 2a [3-20] 2e 2c 29 29 }
    $xor_46 = { 35 23 28 22 [3-20] 34 23 25 30 [3-20] 2b 23 2b 29 [3-20] 2d 2f 2a 2a }
    $xor_47 = { 34 22 29 23 [3-20] 35 22 24 31 [3-20] 2a 22 2a 28 [3-20] 2c 2e 2b 2b }
    $xor_48 = { 3b 2d 26 2c [3-20] 3a 2d 2b 3e [3-20] 25 2d 25 27 [3-20] 23 21 24 24 }
    $xor_49 = { 3a 2c 27 2d [3-20] 3b 2c 2a 3f [3-20] 24 2c 24 26 [3-20] 22 20 25 25 }
    $xor_4A = { 39 2f 24 2e [3-20] 38 2f 29 3c [3-20] 27 2f 27 25 [3-20] 21 23 26 26 }
    $xor_4B = { 38 2e 25 2f [3-20] 39 2e 28 3d [3-20] 26 2e 26 24 [3-20] 20 22 27 27 }
    $xor_4C = { 3f 29 22 28 [3-20] 3e 29 2f 3a [3-20] 21 29 21 23 [3-20] 27 25 20 20 }
    $xor_4D = { 3e 28 23 29 [3-20] 3f 28 2e 3b [3-20] 20 28 20 22 [3-20] 26 24 21 21 }
    $xor_4E = { 3d 2b 20 2a [3-20] 3c 2b 2d 38 [3-20] 23 2b 23 21 [3-20] 25 27 22 22 }
    $xor_4F = { 3c 2a 21 2b [3-20] 3d 2a 2c 39 [3-20] 22 2a 22 20 [3-20] 24 26 23 23 }
    $xor_50 = { 23 35 3e 34 [3-20] 22 35 33 26 [3-20] 3d 35 3d 3f [3-20] 3b 39 3c 3c }
    $xor_51 = { 22 34 3f 35 [3-20] 23 34 32 27 [3-20] 3c 34 3c 3e [3-20] 3a 38 3d 3d }
    $xor_52 = { 21 37 3c 36 [3-20] 20 37 31 24 [3-20] 3f 37 3f 3d [3-20] 39 3b 3e 3e }
    $xor_53 = { 20 36 3d 37 [3-20] 21 36 30 25 [3-20] 3e 36 3e 3c [3-20] 38 3a 3f 3f }
    $xor_54 = { 27 31 3a 30 [3-20] 26 31 37 22 [3-20] 39 31 39 3b [3-20] 3f 3d 38 38 }
    $xor_55 = { 26 30 3b 31 [3-20] 27 30 36 23 [3-20] 38 30 38 3a [3-20] 3e 3c 39 39 }
    $xor_56 = { 25 33 38 32 [3-20] 24 33 35 20 [3-20] 3b 33 3b 39 [3-20] 3d 3f 3a 3a }
    $xor_57 = { 24 32 39 33 [3-20] 25 32 34 21 [3-20] 3a 32 3a 38 [3-20] 3c 3e 3b 3b }
    $xor_58 = { 2b 3d 36 3c [3-20] 2a 3d 3b 2e [3-20] 35 3d 35 37 [3-20] 33 31 34 34 }
    $xor_59 = { 2a 3c 37 3d [3-20] 2b 3c 3a 2f [3-20] 34 3c 34 36 [3-20] 32 30 35 35 }
    $xor_5A = { 29 3f 34 3e [3-20] 28 3f 39 2c [3-20] 37 3f 37 35 [3-20] 31 33 36 36 }
    $xor_5B = { 28 3e 35 3f [3-20] 29 3e 38 2d [3-20] 36 3e 36 34 [3-20] 30 32 37 37 }
    $xor_5C = { 2f 39 32 38 [3-20] 2e 39 3f 2a [3-20] 31 39 31 33 [3-20] 37 35 30 30 }
    $xor_5D = { 2e 38 33 39 [3-20] 2f 38 3e 2b [3-20] 30 38 30 32 [3-20] 36 34 31 31 }
    $xor_5E = { 2d 3b 30 3a [3-20] 2c 3b 3d 28 [3-20] 33 3b 33 31 [3-20] 35 37 32 32 }
    $xor_5F = { 2c 3a 31 3b [3-20] 2d 3a 3c 29 [3-20] 32 3a 32 30 [3-20] 34 36 33 33 }
    $xor_60 = { 13 05 0e 04 [3-20] 12 05 03 16 [3-20] 0d 05 0d 0f [3-20] 0b 09 0c 0c }
    $xor_61 = { 12 04 0f 05 [3-20] 13 04 02 17 [3-20] 0c 04 0c 0e [3-20] 0a 08 0d 0d }
    $xor_62 = { 11 07 0c 06 [3-20] 10 07 01 14 [3-20] 0f 07 0f 0d [3-20] 09 0b 0e 0e }
    $xor_63 = { 10 06 0d 07 [3-20] 11 06 00 15 [3-20] 0e 06 0e 0c [3-20] 08 0a 0f 0f }
    $xor_64 = { 17 01 0a 00 [3-20] 16 01 07 12 [3-20] 09 01 09 0b [3-20] 0f 0d 08 08 }
    $xor_65 = { 16 00 0b 01 [3-20] 17 00 06 13 [3-20] 08 00 08 0a [3-20] 0e 0c 09 09 }
    $xor_66 = { 15 03 08 02 [3-20] 14 03 05 10 [3-20] 0b 03 0b 09 [3-20] 0d 0f 0a 0a }
    $xor_67 = { 14 02 09 03 [3-20] 15 02 04 11 [3-20] 0a 02 0a 08 [3-20] 0c 0e 0b 0b }
    $xor_68 = { 1b 0d 06 0c [3-20] 1a 0d 0b 1e [3-20] 05 0d 05 07 [3-20] 03 01 04 04 }
    $xor_69 = { 1a 0c 07 0d [3-20] 1b 0c 0a 1f [3-20] 04 0c 04 06 [3-20] 02 00 05 05 }
    $xor_6A = { 19 0f 04 0e [3-20] 18 0f 09 1c [3-20] 07 0f 07 05 [3-20] 01 03 06 06 }
    $xor_6B = { 18 0e 05 0f [3-20] 19 0e 08 1d [3-20] 06 0e 06 04 [3-20] 00 02 07 07 }
    $xor_6C = { 1f 09 02 08 [3-20] 1e 09 0f 1a [3-20] 01 09 01 03 [3-20] 07 05 00 00 }
    $xor_6D = { 1e 08 03 09 [3-20] 1f 08 0e 1b [3-20] 00 08 00 02 [3-20] 06 04 01 01 }
    $xor_6E = { 1d 0b 00 0a [3-20] 1c 0b 0d 18 [3-20] 03 0b 03 01 [3-20] 05 07 02 02 }
    $xor_6F = { 1c 0a 01 0b [3-20] 1d 0a 0c 19 [3-20] 02 0a 02 00 [3-20] 04 06 03 03 }
    $xor_70 = { 03 15 1e 14 [3-20] 02 15 13 06 [3-20] 1d 15 1d 1f [3-20] 1b 19 1c 1c }
    $xor_71 = { 02 14 1f 15 [3-20] 03 14 12 07 [3-20] 1c 14 1c 1e [3-20] 1a 18 1d 1d }
    $xor_72 = { 01 17 1c 16 [3-20] 00 17 11 04 [3-20] 1f 17 1f 1d [3-20] 19 1b 1e 1e }
    $xor_73 = { 00 16 1d 17 [3-20] 01 16 10 05 [3-20] 1e 16 1e 1c [3-20] 18 1a 1f 1f }
    $xor_74 = { 07 11 1a 10 [3-20] 06 11 17 02 [3-20] 19 11 19 1b [3-20] 1f 1d 18 18 }
    $xor_75 = { 06 10 1b 11 [3-20] 07 10 16 03 [3-20] 18 10 18 1a [3-20] 1e 1c 19 19 }
    $xor_76 = { 05 13 18 12 [3-20] 04 13 15 00 [3-20] 1b 13 1b 19 [3-20] 1d 1f 1a 1a }
    $xor_77 = { 04 12 19 13 [3-20] 05 12 14 01 [3-20] 1a 12 1a 18 [3-20] 1c 1e 1b 1b }
    $xor_78 = { 0b 1d 16 1c [3-20] 0a 1d 1b 0e [3-20] 15 1d 15 17 [3-20] 13 11 14 14 }
    $xor_79 = { 0a 1c 17 1d [3-20] 0b 1c 1a 0f [3-20] 14 1c 14 16 [3-20] 12 10 15 15 }
    $xor_7A = { 09 1f 14 1e [3-20] 08 1f 19 0c [3-20] 17 1f 17 15 [3-20] 11 13 16 16 }
    $xor_7B = { 08 1e 15 1f [3-20] 09 1e 18 0d [3-20] 16 1e 16 14 [3-20] 10 12 17 17 }
    $xor_7C = { 0f 19 12 18 [3-20] 0e 19 1f 0a [3-20] 11 19 11 13 [3-20] 17 15 10 10 }
    $xor_7D = { 0e 18 13 19 [3-20] 0f 18 1e 0b [3-20] 10 18 10 12 [3-20] 16 14 11 11 }
    $xor_7E = { 0d 1b 10 1a [3-20] 0c 1b 1d 08 [3-20] 13 1b 13 11 [3-20] 15 17 12 12 }
    $xor_7F = { 0c 1a 11 1b [3-20] 0d 1a 1c 09 [3-20] 12 1a 12 10 [3-20] 14 16 13 13 }
    $xor_80 = { f3 e5 ee e4 [3-20] f2 e5 e3 f6 [3-20] ed e5 ed ef [3-20] eb e9 ec ec }
    $xor_81 = { f2 e4 ef e5 [3-20] f3 e4 e2 f7 [3-20] ec e4 ec ee [3-20] ea e8 ed ed }
    $xor_82 = { f1 e7 ec e6 [3-20] f0 e7 e1 f4 [3-20] ef e7 ef ed [3-20] e9 eb ee ee }
    $xor_83 = { f0 e6 ed e7 [3-20] f1 e6 e0 f5 [3-20] ee e6 ee ec [3-20] e8 ea ef ef }
    $xor_84 = { f7 e1 ea e0 [3-20] f6 e1 e7 f2 [3-20] e9 e1 e9 eb [3-20] ef ed e8 e8 }
    $xor_85 = { f6 e0 eb e1 [3-20] f7 e0 e6 f3 [3-20] e8 e0 e8 ea [3-20] ee ec e9 e9 }
    $xor_86 = { f5 e3 e8 e2 [3-20] f4 e3 e5 f0 [3-20] eb e3 eb e9 [3-20] ed ef ea ea }
    $xor_87 = { f4 e2 e9 e3 [3-20] f5 e2 e4 f1 [3-20] ea e2 ea e8 [3-20] ec ee eb eb }
    $xor_88 = { fb ed e6 ec [3-20] fa ed eb fe [3-20] e5 ed e5 e7 [3-20] e3 e1 e4 e4 }
    $xor_89 = { fa ec e7 ed [3-20] fb ec ea ff [3-20] e4 ec e4 e6 [3-20] e2 e0 e5 e5 }
    $xor_8A = { f9 ef e4 ee [3-20] f8 ef e9 fc [3-20] e7 ef e7 e5 [3-20] e1 e3 e6 e6 }
    $xor_8B = { f8 ee e5 ef [3-20] f9 ee e8 fd [3-20] e6 ee e6 e4 [3-20] e0 e2 e7 e7 }
    $xor_8C = { ff e9 e2 e8 [3-20] fe e9 ef fa [3-20] e1 e9 e1 e3 [3-20] e7 e5 e0 e0 }
    $xor_8D = { fe e8 e3 e9 [3-20] ff e8 ee fb [3-20] e0 e8 e0 e2 [3-20] e6 e4 e1 e1 }
    $xor_8E = { fd eb e0 ea [3-20] fc eb ed f8 [3-20] e3 eb e3 e1 [3-20] e5 e7 e2 e2 }
    $xor_8F = { fc ea e1 eb [3-20] fd ea ec f9 [3-20] e2 ea e2 e0 [3-20] e4 e6 e3 e3 }
    $xor_90 = { e3 f5 fe f4 [3-20] e2 f5 f3 e6 [3-20] fd f5 fd ff [3-20] fb f9 fc fc }
    $xor_91 = { e2 f4 ff f5 [3-20] e3 f4 f2 e7 [3-20] fc f4 fc fe [3-20] fa f8 fd fd }
    $xor_92 = { e1 f7 fc f6 [3-20] e0 f7 f1 e4 [3-20] ff f7 ff fd [3-20] f9 fb fe fe }
    $xor_93 = { e0 f6 fd f7 [3-20] e1 f6 f0 e5 [3-20] fe f6 fe fc [3-20] f8 fa ff ff }
    $xor_94 = { e7 f1 fa f0 [3-20] e6 f1 f7 e2 [3-20] f9 f1 f9 fb [3-20] ff fd f8 f8 }
    $xor_95 = { e6 f0 fb f1 [3-20] e7 f0 f6 e3 [3-20] f8 f0 f8 fa [3-20] fe fc f9 f9 }
    $xor_96 = { e5 f3 f8 f2 [3-20] e4 f3 f5 e0 [3-20] fb f3 fb f9 [3-20] fd ff fa fa }
    $xor_97 = { e4 f2 f9 f3 [3-20] e5 f2 f4 e1 [3-20] fa f2 fa f8 [3-20] fc fe fb fb }
    $xor_98 = { eb fd f6 fc [3-20] ea fd fb ee [3-20] f5 fd f5 f7 [3-20] f3 f1 f4 f4 }
    $xor_99 = { ea fc f7 fd [3-20] eb fc fa ef [3-20] f4 fc f4 f6 [3-20] f2 f0 f5 f5 }
    $xor_9A = { e9 ff f4 fe [3-20] e8 ff f9 ec [3-20] f7 ff f7 f5 [3-20] f1 f3 f6 f6 }
    $xor_9B = { e8 fe f5 ff [3-20] e9 fe f8 ed [3-20] f6 fe f6 f4 [3-20] f0 f2 f7 f7 }
    $xor_9C = { ef f9 f2 f8 [3-20] ee f9 ff ea [3-20] f1 f9 f1 f3 [3-20] f7 f5 f0 f0 }
    $xor_9D = { ee f8 f3 f9 [3-20] ef f8 fe eb [3-20] f0 f8 f0 f2 [3-20] f6 f4 f1 f1 }
    $xor_9E = { ed fb f0 fa [3-20] ec fb fd e8 [3-20] f3 fb f3 f1 [3-20] f5 f7 f2 f2 }
    $xor_9F = { ec fa f1 fb [3-20] ed fa fc e9 [3-20] f2 fa f2 f0 [3-20] f4 f6 f3 f3 }
    $xor_A0 = { d3 c5 ce c4 [3-20] d2 c5 c3 d6 [3-20] cd c5 cd cf [3-20] cb c9 cc cc }
    $xor_A1 = { d2 c4 cf c5 [3-20] d3 c4 c2 d7 [3-20] cc c4 cc ce [3-20] ca c8 cd cd }
    $xor_A2 = { d1 c7 cc c6 [3-20] d0 c7 c1 d4 [3-20] cf c7 cf cd [3-20] c9 cb ce ce }
    $xor_A3 = { d0 c6 cd c7 [3-20] d1 c6 c0 d5 [3-20] ce c6 ce cc [3-20] c8 ca cf cf }
    $xor_A4 = { d7 c1 ca c0 [3-20] d6 c1 c7 d2 [3-20] c9 c1 c9 cb [3-20] cf cd c8 c8 }
    $xor_A5 = { d6 c0 cb c1 [3-20] d7 c0 c6 d3 [3-20] c8 c0 c8 ca [3-20] ce cc c9 c9 }
    $xor_A6 = { d5 c3 c8 c2 [3-20] d4 c3 c5 d0 [3-20] cb c3 cb c9 [3-20] cd cf ca ca }
    $xor_A7 = { d4 c2 c9 c3 [3-20] d5 c2 c4 d1 [3-20] ca c2 ca c8 [3-20] cc ce cb cb }
    $xor_A8 = { db cd c6 cc [3-20] da cd cb de [3-20] c5 cd c5 c7 [3-20] c3 c1 c4 c4 }
    $xor_A9 = { da cc c7 cd [3-20] db cc ca df [3-20] c4 cc c4 c6 [3-20] c2 c0 c5 c5 }
    $xor_AA = { d9 cf c4 ce [3-20] d8 cf c9 dc [3-20] c7 cf c7 c5 [3-20] c1 c3 c6 c6 }
    $xor_AB = { d8 ce c5 cf [3-20] d9 ce c8 dd [3-20] c6 ce c6 c4 [3-20] c0 c2 c7 c7 }
    $xor_AC = { df c9 c2 c8 [3-20] de c9 cf da [3-20] c1 c9 c1 c3 [3-20] c7 c5 c0 c0 }
    $xor_AD = { de c8 c3 c9 [3-20] df c8 ce db [3-20] c0 c8 c0 c2 [3-20] c6 c4 c1 c1 }
    $xor_AE = { dd cb c0 ca [3-20] dc cb cd d8 [3-20] c3 cb c3 c1 [3-20] c5 c7 c2 c2 }
    $xor_AF = { dc ca c1 cb [3-20] dd ca cc d9 [3-20] c2 ca c2 c0 [3-20] c4 c6 c3 c3 }
    $xor_B0 = { c3 d5 de d4 [3-20] c2 d5 d3 c6 [3-20] dd d5 dd df [3-20] db d9 dc dc }
    $xor_B1 = { c2 d4 df d5 [3-20] c3 d4 d2 c7 [3-20] dc d4 dc de [3-20] da d8 dd dd }
    $xor_B2 = { c1 d7 dc d6 [3-20] c0 d7 d1 c4 [3-20] df d7 df dd [3-20] d9 db de de }
    $xor_B3 = { c0 d6 dd d7 [3-20] c1 d6 d0 c5 [3-20] de d6 de dc [3-20] d8 da df df }
    $xor_B4 = { c7 d1 da d0 [3-20] c6 d1 d7 c2 [3-20] d9 d1 d9 db [3-20] df dd d8 d8 }
    $xor_B5 = { c6 d0 db d1 [3-20] c7 d0 d6 c3 [3-20] d8 d0 d8 da [3-20] de dc d9 d9 }
    $xor_B6 = { c5 d3 d8 d2 [3-20] c4 d3 d5 c0 [3-20] db d3 db d9 [3-20] dd df da da }
    $xor_B7 = { c4 d2 d9 d3 [3-20] c5 d2 d4 c1 [3-20] da d2 da d8 [3-20] dc de db db }
    $xor_B8 = { cb dd d6 dc [3-20] ca dd db ce [3-20] d5 dd d5 d7 [3-20] d3 d1 d4 d4 }
    $xor_B9 = { ca dc d7 dd [3-20] cb dc da cf [3-20] d4 dc d4 d6 [3-20] d2 d0 d5 d5 }
    $xor_BA = { c9 df d4 de [3-20] c8 df d9 cc [3-20] d7 df d7 d5 [3-20] d1 d3 d6 d6 }
    $xor_BB = { c8 de d5 df [3-20] c9 de d8 cd [3-20] d6 de d6 d4 [3-20] d0 d2 d7 d7 }
    $xor_BC = { cf d9 d2 d8 [3-20] ce d9 df ca [3-20] d1 d9 d1 d3 [3-20] d7 d5 d0 d0 }
    $xor_BD = { ce d8 d3 d9 [3-20] cf d8 de cb [3-20] d0 d8 d0 d2 [3-20] d6 d4 d1 d1 }
    $xor_BE = { cd db d0 da [3-20] cc db dd c8 [3-20] d3 db d3 d1 [3-20] d5 d7 d2 d2 }
    $xor_BF = { cc da d1 db [3-20] cd da dc c9 [3-20] d2 da d2 d0 [3-20] d4 d6 d3 d3 }
    $xor_C0 = { b3 a5 ae a4 [3-20] b2 a5 a3 b6 [3-20] ad a5 ad af [3-20] ab a9 ac ac }
    $xor_C1 = { b2 a4 af a5 [3-20] b3 a4 a2 b7 [3-20] ac a4 ac ae [3-20] aa a8 ad ad }
    $xor_C2 = { b1 a7 ac a6 [3-20] b0 a7 a1 b4 [3-20] af a7 af ad [3-20] a9 ab ae ae }
    $xor_C3 = { b0 a6 ad a7 [3-20] b1 a6 a0 b5 [3-20] ae a6 ae ac [3-20] a8 aa af af }
    $xor_C4 = { b7 a1 aa a0 [3-20] b6 a1 a7 b2 [3-20] a9 a1 a9 ab [3-20] af ad a8 a8 }
    $xor_C5 = { b6 a0 ab a1 [3-20] b7 a0 a6 b3 [3-20] a8 a0 a8 aa [3-20] ae ac a9 a9 }
    $xor_C6 = { b5 a3 a8 a2 [3-20] b4 a3 a5 b0 [3-20] ab a3 ab a9 [3-20] ad af aa aa }
    $xor_C7 = { b4 a2 a9 a3 [3-20] b5 a2 a4 b1 [3-20] aa a2 aa a8 [3-20] ac ae ab ab }
    $xor_C8 = { bb ad a6 ac [3-20] ba ad ab be [3-20] a5 ad a5 a7 [3-20] a3 a1 a4 a4 }
    $xor_C9 = { ba ac a7 ad [3-20] bb ac aa bf [3-20] a4 ac a4 a6 [3-20] a2 a0 a5 a5 }
    $xor_CA = { b9 af a4 ae [3-20] b8 af a9 bc [3-20] a7 af a7 a5 [3-20] a1 a3 a6 a6 }
    $xor_CB = { b8 ae a5 af [3-20] b9 ae a8 bd [3-20] a6 ae a6 a4 [3-20] a0 a2 a7 a7 }
    $xor_CC = { bf a9 a2 a8 [3-20] be a9 af ba [3-20] a1 a9 a1 a3 [3-20] a7 a5 a0 a0 }
    $xor_CD = { be a8 a3 a9 [3-20] bf a8 ae bb [3-20] a0 a8 a0 a2 [3-20] a6 a4 a1 a1 }
    $xor_CE = { bd ab a0 aa [3-20] bc ab ad b8 [3-20] a3 ab a3 a1 [3-20] a5 a7 a2 a2 }
    $xor_CF = { bc aa a1 ab [3-20] bd aa ac b9 [3-20] a2 aa a2 a0 [3-20] a4 a6 a3 a3 }
    $xor_D0 = { a3 b5 be b4 [3-20] a2 b5 b3 a6 [3-20] bd b5 bd bf [3-20] bb b9 bc bc }
    $xor_D1 = { a2 b4 bf b5 [3-20] a3 b4 b2 a7 [3-20] bc b4 bc be [3-20] ba b8 bd bd }
    $xor_D2 = { a1 b7 bc b6 [3-20] a0 b7 b1 a4 [3-20] bf b7 bf bd [3-20] b9 bb be be }
    $xor_D3 = { a0 b6 bd b7 [3-20] a1 b6 b0 a5 [3-20] be b6 be bc [3-20] b8 ba bf bf }
    $xor_D4 = { a7 b1 ba b0 [3-20] a6 b1 b7 a2 [3-20] b9 b1 b9 bb [3-20] bf bd b8 b8 }
    $xor_D5 = { a6 b0 bb b1 [3-20] a7 b0 b6 a3 [3-20] b8 b0 b8 ba [3-20] be bc b9 b9 }
    $xor_D6 = { a5 b3 b8 b2 [3-20] a4 b3 b5 a0 [3-20] bb b3 bb b9 [3-20] bd bf ba ba }
    $xor_D7 = { a4 b2 b9 b3 [3-20] a5 b2 b4 a1 [3-20] ba b2 ba b8 [3-20] bc be bb bb }
    $xor_D8 = { ab bd b6 bc [3-20] aa bd bb ae [3-20] b5 bd b5 b7 [3-20] b3 b1 b4 b4 }
    $xor_D9 = { aa bc b7 bd [3-20] ab bc ba af [3-20] b4 bc b4 b6 [3-20] b2 b0 b5 b5 }
    $xor_DA = { a9 bf b4 be [3-20] a8 bf b9 ac [3-20] b7 bf b7 b5 [3-20] b1 b3 b6 b6 }
    $xor_DB = { a8 be b5 bf [3-20] a9 be b8 ad [3-20] b6 be b6 b4 [3-20] b0 b2 b7 b7 }
    $xor_DC = { af b9 b2 b8 [3-20] ae b9 bf aa [3-20] b1 b9 b1 b3 [3-20] b7 b5 b0 b0 }
    $xor_DD = { ae b8 b3 b9 [3-20] af b8 be ab [3-20] b0 b8 b0 b2 [3-20] b6 b4 b1 b1 }
    $xor_DE = { ad bb b0 ba [3-20] ac bb bd a8 [3-20] b3 bb b3 b1 [3-20] b5 b7 b2 b2 }
    $xor_DF = { ac ba b1 bb [3-20] ad ba bc a9 [3-20] b2 ba b2 b0 [3-20] b4 b6 b3 b3 }
    $xor_E0 = { 93 85 8e 84 [3-20] 92 85 83 96 [3-20] 8d 85 8d 8f [3-20] 8b 89 8c 8c }
    $xor_E1 = { 92 84 8f 85 [3-20] 93 84 82 97 [3-20] 8c 84 8c 8e [3-20] 8a 88 8d 8d }
    $xor_E2 = { 91 87 8c 86 [3-20] 90 87 81 94 [3-20] 8f 87 8f 8d [3-20] 89 8b 8e 8e }
    $xor_E3 = { 90 86 8d 87 [3-20] 91 86 80 95 [3-20] 8e 86 8e 8c [3-20] 88 8a 8f 8f }
    $xor_E4 = { 97 81 8a 80 [3-20] 96 81 87 92 [3-20] 89 81 89 8b [3-20] 8f 8d 88 88 }
    $xor_E5 = { 96 80 8b 81 [3-20] 97 80 86 93 [3-20] 88 80 88 8a [3-20] 8e 8c 89 89 }
    $xor_E6 = { 95 83 88 82 [3-20] 94 83 85 90 [3-20] 8b 83 8b 89 [3-20] 8d 8f 8a 8a }
    $xor_E7 = { 94 82 89 83 [3-20] 95 82 84 91 [3-20] 8a 82 8a 88 [3-20] 8c 8e 8b 8b }
    $xor_E8 = { 9b 8d 86 8c [3-20] 9a 8d 8b 9e [3-20] 85 8d 85 87 [3-20] 83 81 84 84 }
    $xor_E9 = { 9a 8c 87 8d [3-20] 9b 8c 8a 9f [3-20] 84 8c 84 86 [3-20] 82 80 85 85 }
    $xor_EA = { 99 8f 84 8e [3-20] 98 8f 89 9c [3-20] 87 8f 87 85 [3-20] 81 83 86 86 }
    $xor_EB = { 98 8e 85 8f [3-20] 99 8e 88 9d [3-20] 86 8e 86 84 [3-20] 80 82 87 87 }
    $xor_EC = { 9f 89 82 88 [3-20] 9e 89 8f 9a [3-20] 81 89 81 83 [3-20] 87 85 80 80 }
    $xor_ED = { 9e 88 83 89 [3-20] 9f 88 8e 9b [3-20] 80 88 80 82 [3-20] 86 84 81 81 }
    $xor_EE = { 9d 8b 80 8a [3-20] 9c 8b 8d 98 [3-20] 83 8b 83 81 [3-20] 85 87 82 82 }
    $xor_EF = { 9c 8a 81 8b [3-20] 9d 8a 8c 99 [3-20] 82 8a 82 80 [3-20] 84 86 83 83 }
    $xor_F0 = { 83 95 9e 94 [3-20] 82 95 93 86 [3-20] 9d 95 9d 9f [3-20] 9b 99 9c 9c }
    $xor_F1 = { 82 94 9f 95 [3-20] 83 94 92 87 [3-20] 9c 94 9c 9e [3-20] 9a 98 9d 9d }
    $xor_F2 = { 81 97 9c 96 [3-20] 80 97 91 84 [3-20] 9f 97 9f 9d [3-20] 99 9b 9e 9e }
    $xor_F3 = { 80 96 9d 97 [3-20] 81 96 90 85 [3-20] 9e 96 9e 9c [3-20] 98 9a 9f 9f }
    $xor_F4 = { 87 91 9a 90 [3-20] 86 91 97 82 [3-20] 99 91 99 9b [3-20] 9f 9d 98 98 }
    $xor_F5 = { 86 90 9b 91 [3-20] 87 90 96 83 [3-20] 98 90 98 9a [3-20] 9e 9c 99 99 }
    $xor_F6 = { 85 93 98 92 [3-20] 84 93 95 80 [3-20] 9b 93 9b 99 [3-20] 9d 9f 9a 9a }
    $xor_F7 = { 84 92 99 93 [3-20] 85 92 94 81 [3-20] 9a 92 9a 98 [3-20] 9c 9e 9b 9b }
    $xor_F8 = { 8b 9d 96 9c [3-20] 8a 9d 9b 8e [3-20] 95 9d 95 97 [3-20] 93 91 94 94 }
    $xor_F9 = { 8a 9c 97 9d [3-20] 8b 9c 9a 8f [3-20] 94 9c 94 96 [3-20] 92 90 95 95 }
    $xor_FA = { 89 9f 94 9e [3-20] 88 9f 99 8c [3-20] 97 9f 97 95 [3-20] 91 93 96 96 }
    $xor_FB = { 88 9e 95 9f [3-20] 89 9e 98 8d [3-20] 96 9e 96 94 [3-20] 90 92 97 97 }
    $xor_FC = { 8f 99 92 98 [3-20] 8e 99 9f 8a [3-20] 91 99 91 93 [3-20] 97 95 90 90 }
    $xor_FD = { 8e 98 93 99 [3-20] 8f 98 9e 8b [3-20] 90 98 90 92 [3-20] 96 94 91 91 }
    $xor_FE = { 8d 9b 90 9a [3-20] 8c 9b 9d 88 [3-20] 93 9b 93 91 [3-20] 95 97 92 92 }
    $xor_FF = { 8c 9a 91 9b [3-20] 8d 9a 9c 89 [3-20] 92 9a 92 90 [3-20] 94 96 93 93 }


  condition:
    (uint16(0) == 0x5a4d) and any of them
}


rule malware_lodeinfo_network_decode_process_xor_bruteforce
{
  meta:
    description = "Rule to detect network decode process in LODEINFO"
    author = "JPCERT/CC Incident Response Group"
    hash = "2169d93f344e3f353444557b9009aef27f1b0a0a8aa3d947b5b8f0b36ef20672"

  strings:
    $xor_01 = { 8b 4f 35 31 4f 31 31 4f 30 31 4f 33 31 4f 32 f7 47 31 0e }
    $xor_02 = { 88 4c 36 32 4c 32 32 4c 33 32 4c 30 32 4c 31 f4 44 32 0d }
    $xor_03 = { 89 4d 37 33 4d 33 33 4d 32 33 4d 31 33 4d 30 f5 45 33 0c }
    $xor_04 = { 8e 4a 30 34 4a 34 34 4a 35 34 4a 36 34 4a 37 f2 42 34 0b }
    $xor_05 = { 8f 4b 31 35 4b 35 35 4b 34 35 4b 37 35 4b 36 f3 43 35 0a }
    $xor_06 = { 8c 48 32 36 48 36 36 48 37 36 48 34 36 48 35 f0 40 36 09 }
    $xor_07 = { 8d 49 33 37 49 37 37 49 36 37 49 35 37 49 34 f1 41 37 08 }
    $xor_08 = { 82 46 3c 38 46 38 38 46 39 38 46 3a 38 46 3b fe 4e 38 07 }
    $xor_09 = { 83 47 3d 39 47 39 39 47 38 39 47 3b 39 47 3a ff 4f 39 06 }
    $xor_0A = { 80 44 3e 3a 44 3a 3a 44 3b 3a 44 38 3a 44 39 fc 4c 3a 05 }
    $xor_0B = { 81 45 3f 3b 45 3b 3b 45 3a 3b 45 39 3b 45 38 fd 4d 3b 04 }
    $xor_0C = { 86 42 38 3c 42 3c 3c 42 3d 3c 42 3e 3c 42 3f fa 4a 3c 03 }
    $xor_0D = { 87 43 39 3d 43 3d 3d 43 3c 3d 43 3f 3d 43 3e fb 4b 3d 02 }
    $xor_0E = { 84 40 3a 3e 40 3e 3e 40 3f 3e 40 3c 3e 40 3d f8 48 3e 01 }
    $xor_0F = { 85 41 3b 3f 41 3f 3f 41 3e 3f 41 3d 3f 41 3c f9 49 3f 00 }
    $xor_10 = { 9a 5e 24 20 5e 20 20 5e 21 20 5e 22 20 5e 23 e6 56 20 1f }
    $xor_11 = { 9b 5f 25 21 5f 21 21 5f 20 21 5f 23 21 5f 22 e7 57 21 1e }
    $xor_12 = { 98 5c 26 22 5c 22 22 5c 23 22 5c 20 22 5c 21 e4 54 22 1d }
    $xor_13 = { 99 5d 27 23 5d 23 23 5d 22 23 5d 21 23 5d 20 e5 55 23 1c }
    $xor_14 = { 9e 5a 20 24 5a 24 24 5a 25 24 5a 26 24 5a 27 e2 52 24 1b }
    $xor_15 = { 9f 5b 21 25 5b 25 25 5b 24 25 5b 27 25 5b 26 e3 53 25 1a }
    $xor_16 = { 9c 58 22 26 58 26 26 58 27 26 58 24 26 58 25 e0 50 26 19 }
    $xor_17 = { 9d 59 23 27 59 27 27 59 26 27 59 25 27 59 24 e1 51 27 18 }
    $xor_18 = { 92 56 2c 28 56 28 28 56 29 28 56 2a 28 56 2b ee 5e 28 17 }
    $xor_19 = { 93 57 2d 29 57 29 29 57 28 29 57 2b 29 57 2a ef 5f 29 16 }
    $xor_1A = { 90 54 2e 2a 54 2a 2a 54 2b 2a 54 28 2a 54 29 ec 5c 2a 15 }
    $xor_1B = { 91 55 2f 2b 55 2b 2b 55 2a 2b 55 29 2b 55 28 ed 5d 2b 14 }
    $xor_1C = { 96 52 28 2c 52 2c 2c 52 2d 2c 52 2e 2c 52 2f ea 5a 2c 13 }
    $xor_1D = { 97 53 29 2d 53 2d 2d 53 2c 2d 53 2f 2d 53 2e eb 5b 2d 12 }
    $xor_1E = { 94 50 2a 2e 50 2e 2e 50 2f 2e 50 2c 2e 50 2d e8 58 2e 11 }
    $xor_1F = { 95 51 2b 2f 51 2f 2f 51 2e 2f 51 2d 2f 51 2c e9 59 2f 10 }
    $xor_20 = { aa 6e 14 10 6e 10 10 6e 11 10 6e 12 10 6e 13 d6 66 10 2f }
    $xor_21 = { ab 6f 15 11 6f 11 11 6f 10 11 6f 13 11 6f 12 d7 67 11 2e }
    $xor_22 = { a8 6c 16 12 6c 12 12 6c 13 12 6c 10 12 6c 11 d4 64 12 2d }
    $xor_23 = { a9 6d 17 13 6d 13 13 6d 12 13 6d 11 13 6d 10 d5 65 13 2c }
    $xor_24 = { ae 6a 10 14 6a 14 14 6a 15 14 6a 16 14 6a 17 d2 62 14 2b }
    $xor_25 = { af 6b 11 15 6b 15 15 6b 14 15 6b 17 15 6b 16 d3 63 15 2a }
    $xor_26 = { ac 68 12 16 68 16 16 68 17 16 68 14 16 68 15 d0 60 16 29 }
    $xor_27 = { ad 69 13 17 69 17 17 69 16 17 69 15 17 69 14 d1 61 17 28 }
    $xor_28 = { a2 66 1c 18 66 18 18 66 19 18 66 1a 18 66 1b de 6e 18 27 }
    $xor_29 = { a3 67 1d 19 67 19 19 67 18 19 67 1b 19 67 1a df 6f 19 26 }
    $xor_2A = { a0 64 1e 1a 64 1a 1a 64 1b 1a 64 18 1a 64 19 dc 6c 1a 25 }
    $xor_2B = { a1 65 1f 1b 65 1b 1b 65 1a 1b 65 19 1b 65 18 dd 6d 1b 24 }
    $xor_2C = { a6 62 18 1c 62 1c 1c 62 1d 1c 62 1e 1c 62 1f da 6a 1c 23 }
    $xor_2D = { a7 63 19 1d 63 1d 1d 63 1c 1d 63 1f 1d 63 1e db 6b 1d 22 }
    $xor_2E = { a4 60 1a 1e 60 1e 1e 60 1f 1e 60 1c 1e 60 1d d8 68 1e 21 }
    $xor_2F = { a5 61 1b 1f 61 1f 1f 61 1e 1f 61 1d 1f 61 1c d9 69 1f 20 }
    $xor_30 = { ba 7e 04 00 7e 00 00 7e 01 00 7e 02 00 7e 03 c6 76 00 3f }
    $xor_31 = { bb 7f 05 01 7f 01 01 7f 00 01 7f 03 01 7f 02 c7 77 01 3e }
    $xor_32 = { b8 7c 06 02 7c 02 02 7c 03 02 7c 00 02 7c 01 c4 74 02 3d }
    $xor_33 = { b9 7d 07 03 7d 03 03 7d 02 03 7d 01 03 7d 00 c5 75 03 3c }
    $xor_34 = { be 7a 00 04 7a 04 04 7a 05 04 7a 06 04 7a 07 c2 72 04 3b }
    $xor_35 = { bf 7b 01 05 7b 05 05 7b 04 05 7b 07 05 7b 06 c3 73 05 3a }
    $xor_36 = { bc 78 02 06 78 06 06 78 07 06 78 04 06 78 05 c0 70 06 39 }
    $xor_37 = { bd 79 03 07 79 07 07 79 06 07 79 05 07 79 04 c1 71 07 38 }
    $xor_38 = { b2 76 0c 08 76 08 08 76 09 08 76 0a 08 76 0b ce 7e 08 37 }
    $xor_39 = { b3 77 0d 09 77 09 09 77 08 09 77 0b 09 77 0a cf 7f 09 36 }
    $xor_3A = { b0 74 0e 0a 74 0a 0a 74 0b 0a 74 08 0a 74 09 cc 7c 0a 35 }
    $xor_3B = { b1 75 0f 0b 75 0b 0b 75 0a 0b 75 09 0b 75 08 cd 7d 0b 34 }
    $xor_3C = { b6 72 08 0c 72 0c 0c 72 0d 0c 72 0e 0c 72 0f ca 7a 0c 33 }
    $xor_3D = { b7 73 09 0d 73 0d 0d 73 0c 0d 73 0f 0d 73 0e cb 7b 0d 32 }
    $xor_3E = { b4 70 0a 0e 70 0e 0e 70 0f 0e 70 0c 0e 70 0d c8 78 0e 31 }
    $xor_3F = { b5 71 0b 0f 71 0f 0f 71 0e 0f 71 0d 0f 71 0c c9 79 0f 30 }
    $xor_40 = { ca 0e 74 70 0e 70 70 0e 71 70 0e 72 70 0e 73 b6 06 70 4f }
    $xor_41 = { cb 0f 75 71 0f 71 71 0f 70 71 0f 73 71 0f 72 b7 07 71 4e }
    $xor_42 = { c8 0c 76 72 0c 72 72 0c 73 72 0c 70 72 0c 71 b4 04 72 4d }
    $xor_43 = { c9 0d 77 73 0d 73 73 0d 72 73 0d 71 73 0d 70 b5 05 73 4c }
    $xor_44 = { ce 0a 70 74 0a 74 74 0a 75 74 0a 76 74 0a 77 b2 02 74 4b }
    $xor_45 = { cf 0b 71 75 0b 75 75 0b 74 75 0b 77 75 0b 76 b3 03 75 4a }
    $xor_46 = { cc 08 72 76 08 76 76 08 77 76 08 74 76 08 75 b0 00 76 49 }
    $xor_47 = { cd 09 73 77 09 77 77 09 76 77 09 75 77 09 74 b1 01 77 48 }
    $xor_48 = { c2 06 7c 78 06 78 78 06 79 78 06 7a 78 06 7b be 0e 78 47 }
    $xor_49 = { c3 07 7d 79 07 79 79 07 78 79 07 7b 79 07 7a bf 0f 79 46 }
    $xor_4A = { c0 04 7e 7a 04 7a 7a 04 7b 7a 04 78 7a 04 79 bc 0c 7a 45 }
    $xor_4B = { c1 05 7f 7b 05 7b 7b 05 7a 7b 05 79 7b 05 78 bd 0d 7b 44 }
    $xor_4C = { c6 02 78 7c 02 7c 7c 02 7d 7c 02 7e 7c 02 7f ba 0a 7c 43 }
    $xor_4D = { c7 03 79 7d 03 7d 7d 03 7c 7d 03 7f 7d 03 7e bb 0b 7d 42 }
    $xor_4E = { c4 00 7a 7e 00 7e 7e 00 7f 7e 00 7c 7e 00 7d b8 08 7e 41 }
    $xor_4F = { c5 01 7b 7f 01 7f 7f 01 7e 7f 01 7d 7f 01 7c b9 09 7f 40 }
    $xor_50 = { da 1e 64 60 1e 60 60 1e 61 60 1e 62 60 1e 63 a6 16 60 5f }
    $xor_51 = { db 1f 65 61 1f 61 61 1f 60 61 1f 63 61 1f 62 a7 17 61 5e }
    $xor_52 = { d8 1c 66 62 1c 62 62 1c 63 62 1c 60 62 1c 61 a4 14 62 5d }
    $xor_53 = { d9 1d 67 63 1d 63 63 1d 62 63 1d 61 63 1d 60 a5 15 63 5c }
    $xor_54 = { de 1a 60 64 1a 64 64 1a 65 64 1a 66 64 1a 67 a2 12 64 5b }
    $xor_55 = { df 1b 61 65 1b 65 65 1b 64 65 1b 67 65 1b 66 a3 13 65 5a }
    $xor_56 = { dc 18 62 66 18 66 66 18 67 66 18 64 66 18 65 a0 10 66 59 }
    $xor_57 = { dd 19 63 67 19 67 67 19 66 67 19 65 67 19 64 a1 11 67 58 }
    $xor_58 = { d2 16 6c 68 16 68 68 16 69 68 16 6a 68 16 6b ae 1e 68 57 }
    $xor_59 = { d3 17 6d 69 17 69 69 17 68 69 17 6b 69 17 6a af 1f 69 56 }
    $xor_5A = { d0 14 6e 6a 14 6a 6a 14 6b 6a 14 68 6a 14 69 ac 1c 6a 55 }
    $xor_5B = { d1 15 6f 6b 15 6b 6b 15 6a 6b 15 69 6b 15 68 ad 1d 6b 54 }
    $xor_5C = { d6 12 68 6c 12 6c 6c 12 6d 6c 12 6e 6c 12 6f aa 1a 6c 53 }
    $xor_5D = { d7 13 69 6d 13 6d 6d 13 6c 6d 13 6f 6d 13 6e ab 1b 6d 52 }
    $xor_5E = { d4 10 6a 6e 10 6e 6e 10 6f 6e 10 6c 6e 10 6d a8 18 6e 51 }
    $xor_5F = { d5 11 6b 6f 11 6f 6f 11 6e 6f 11 6d 6f 11 6c a9 19 6f 50 }
    $xor_60 = { ea 2e 54 50 2e 50 50 2e 51 50 2e 52 50 2e 53 96 26 50 6f }
    $xor_61 = { eb 2f 55 51 2f 51 51 2f 50 51 2f 53 51 2f 52 97 27 51 6e }
    $xor_62 = { e8 2c 56 52 2c 52 52 2c 53 52 2c 50 52 2c 51 94 24 52 6d }
    $xor_63 = { e9 2d 57 53 2d 53 53 2d 52 53 2d 51 53 2d 50 95 25 53 6c }
    $xor_64 = { ee 2a 50 54 2a 54 54 2a 55 54 2a 56 54 2a 57 92 22 54 6b }
    $xor_65 = { ef 2b 51 55 2b 55 55 2b 54 55 2b 57 55 2b 56 93 23 55 6a }
    $xor_66 = { ec 28 52 56 28 56 56 28 57 56 28 54 56 28 55 90 20 56 69 }
    $xor_67 = { ed 29 53 57 29 57 57 29 56 57 29 55 57 29 54 91 21 57 68 }
    $xor_68 = { e2 26 5c 58 26 58 58 26 59 58 26 5a 58 26 5b 9e 2e 58 67 }
    $xor_69 = { e3 27 5d 59 27 59 59 27 58 59 27 5b 59 27 5a 9f 2f 59 66 }
    $xor_6A = { e0 24 5e 5a 24 5a 5a 24 5b 5a 24 58 5a 24 59 9c 2c 5a 65 }
    $xor_6B = { e1 25 5f 5b 25 5b 5b 25 5a 5b 25 59 5b 25 58 9d 2d 5b 64 }
    $xor_6C = { e6 22 58 5c 22 5c 5c 22 5d 5c 22 5e 5c 22 5f 9a 2a 5c 63 }
    $xor_6D = { e7 23 59 5d 23 5d 5d 23 5c 5d 23 5f 5d 23 5e 9b 2b 5d 62 }
    $xor_6E = { e4 20 5a 5e 20 5e 5e 20 5f 5e 20 5c 5e 20 5d 98 28 5e 61 }
    $xor_6F = { e5 21 5b 5f 21 5f 5f 21 5e 5f 21 5d 5f 21 5c 99 29 5f 60 }
    $xor_70 = { fa 3e 44 40 3e 40 40 3e 41 40 3e 42 40 3e 43 86 36 40 7f }
    $xor_71 = { fb 3f 45 41 3f 41 41 3f 40 41 3f 43 41 3f 42 87 37 41 7e }
    $xor_72 = { f8 3c 46 42 3c 42 42 3c 43 42 3c 40 42 3c 41 84 34 42 7d }
    $xor_73 = { f9 3d 47 43 3d 43 43 3d 42 43 3d 41 43 3d 40 85 35 43 7c }
    $xor_74 = { fe 3a 40 44 3a 44 44 3a 45 44 3a 46 44 3a 47 82 32 44 7b }
    $xor_75 = { ff 3b 41 45 3b 45 45 3b 44 45 3b 47 45 3b 46 83 33 45 7a }
    $xor_76 = { fc 38 42 46 38 46 46 38 47 46 38 44 46 38 45 80 30 46 79 }
    $xor_77 = { fd 39 43 47 39 47 47 39 46 47 39 45 47 39 44 81 31 47 78 }
    $xor_78 = { f2 36 4c 48 36 48 48 36 49 48 36 4a 48 36 4b 8e 3e 48 77 }
    $xor_79 = { f3 37 4d 49 37 49 49 37 48 49 37 4b 49 37 4a 8f 3f 49 76 }
    $xor_7A = { f0 34 4e 4a 34 4a 4a 34 4b 4a 34 48 4a 34 49 8c 3c 4a 75 }
    $xor_7B = { f1 35 4f 4b 35 4b 4b 35 4a 4b 35 49 4b 35 48 8d 3d 4b 74 }
    $xor_7C = { f6 32 48 4c 32 4c 4c 32 4d 4c 32 4e 4c 32 4f 8a 3a 4c 73 }
    $xor_7D = { f7 33 49 4d 33 4d 4d 33 4c 4d 33 4f 4d 33 4e 8b 3b 4d 72 }
    $xor_7E = { f4 30 4a 4e 30 4e 4e 30 4f 4e 30 4c 4e 30 4d 88 38 4e 71 }
    $xor_7F = { f5 31 4b 4f 31 4f 4f 31 4e 4f 31 4d 4f 31 4c 89 39 4f 70 }
    $xor_80 = { 0a ce b4 b0 ce b0 b0 ce b1 b0 ce b2 b0 ce b3 76 c6 b0 8f }
    $xor_81 = { 0b cf b5 b1 cf b1 b1 cf b0 b1 cf b3 b1 cf b2 77 c7 b1 8e }
    $xor_82 = { 08 cc b6 b2 cc b2 b2 cc b3 b2 cc b0 b2 cc b1 74 c4 b2 8d }
    $xor_83 = { 09 cd b7 b3 cd b3 b3 cd b2 b3 cd b1 b3 cd b0 75 c5 b3 8c }
    $xor_84 = { 0e ca b0 b4 ca b4 b4 ca b5 b4 ca b6 b4 ca b7 72 c2 b4 8b }
    $xor_85 = { 0f cb b1 b5 cb b5 b5 cb b4 b5 cb b7 b5 cb b6 73 c3 b5 8a }
    $xor_86 = { 0c c8 b2 b6 c8 b6 b6 c8 b7 b6 c8 b4 b6 c8 b5 70 c0 b6 89 }
    $xor_87 = { 0d c9 b3 b7 c9 b7 b7 c9 b6 b7 c9 b5 b7 c9 b4 71 c1 b7 88 }
    $xor_88 = { 02 c6 bc b8 c6 b8 b8 c6 b9 b8 c6 ba b8 c6 bb 7e ce b8 87 }
    $xor_89 = { 03 c7 bd b9 c7 b9 b9 c7 b8 b9 c7 bb b9 c7 ba 7f cf b9 86 }
    $xor_8A = { 00 c4 be ba c4 ba ba c4 bb ba c4 b8 ba c4 b9 7c cc ba 85 }
    $xor_8B = { 01 c5 bf bb c5 bb bb c5 ba bb c5 b9 bb c5 b8 7d cd bb 84 }
    $xor_8C = { 06 c2 b8 bc c2 bc bc c2 bd bc c2 be bc c2 bf 7a ca bc 83 }
    $xor_8D = { 07 c3 b9 bd c3 bd bd c3 bc bd c3 bf bd c3 be 7b cb bd 82 }
    $xor_8E = { 04 c0 ba be c0 be be c0 bf be c0 bc be c0 bd 78 c8 be 81 }
    $xor_8F = { 05 c1 bb bf c1 bf bf c1 be bf c1 bd bf c1 bc 79 c9 bf 80 }
    $xor_90 = { 1a de a4 a0 de a0 a0 de a1 a0 de a2 a0 de a3 66 d6 a0 9f }
    $xor_91 = { 1b df a5 a1 df a1 a1 df a0 a1 df a3 a1 df a2 67 d7 a1 9e }
    $xor_92 = { 18 dc a6 a2 dc a2 a2 dc a3 a2 dc a0 a2 dc a1 64 d4 a2 9d }
    $xor_93 = { 19 dd a7 a3 dd a3 a3 dd a2 a3 dd a1 a3 dd a0 65 d5 a3 9c }
    $xor_94 = { 1e da a0 a4 da a4 a4 da a5 a4 da a6 a4 da a7 62 d2 a4 9b }
    $xor_95 = { 1f db a1 a5 db a5 a5 db a4 a5 db a7 a5 db a6 63 d3 a5 9a }
    $xor_96 = { 1c d8 a2 a6 d8 a6 a6 d8 a7 a6 d8 a4 a6 d8 a5 60 d0 a6 99 }
    $xor_97 = { 1d d9 a3 a7 d9 a7 a7 d9 a6 a7 d9 a5 a7 d9 a4 61 d1 a7 98 }
    $xor_98 = { 12 d6 ac a8 d6 a8 a8 d6 a9 a8 d6 aa a8 d6 ab 6e de a8 97 }
    $xor_99 = { 13 d7 ad a9 d7 a9 a9 d7 a8 a9 d7 ab a9 d7 aa 6f df a9 96 }
    $xor_9A = { 10 d4 ae aa d4 aa aa d4 ab aa d4 a8 aa d4 a9 6c dc aa 95 }
    $xor_9B = { 11 d5 af ab d5 ab ab d5 aa ab d5 a9 ab d5 a8 6d dd ab 94 }
    $xor_9C = { 16 d2 a8 ac d2 ac ac d2 ad ac d2 ae ac d2 af 6a da ac 93 }
    $xor_9D = { 17 d3 a9 ad d3 ad ad d3 ac ad d3 af ad d3 ae 6b db ad 92 }
    $xor_9E = { 14 d0 aa ae d0 ae ae d0 af ae d0 ac ae d0 ad 68 d8 ae 91 }
    $xor_9F = { 15 d1 ab af d1 af af d1 ae af d1 ad af d1 ac 69 d9 af 90 }
    $xor_A0 = { 2a ee 94 90 ee 90 90 ee 91 90 ee 92 90 ee 93 56 e6 90 af }
    $xor_A1 = { 2b ef 95 91 ef 91 91 ef 90 91 ef 93 91 ef 92 57 e7 91 ae }
    $xor_A2 = { 28 ec 96 92 ec 92 92 ec 93 92 ec 90 92 ec 91 54 e4 92 ad }
    $xor_A3 = { 29 ed 97 93 ed 93 93 ed 92 93 ed 91 93 ed 90 55 e5 93 ac }
    $xor_A4 = { 2e ea 90 94 ea 94 94 ea 95 94 ea 96 94 ea 97 52 e2 94 ab }
    $xor_A5 = { 2f eb 91 95 eb 95 95 eb 94 95 eb 97 95 eb 96 53 e3 95 aa }
    $xor_A6 = { 2c e8 92 96 e8 96 96 e8 97 96 e8 94 96 e8 95 50 e0 96 a9 }
    $xor_A7 = { 2d e9 93 97 e9 97 97 e9 96 97 e9 95 97 e9 94 51 e1 97 a8 }
    $xor_A8 = { 22 e6 9c 98 e6 98 98 e6 99 98 e6 9a 98 e6 9b 5e ee 98 a7 }
    $xor_A9 = { 23 e7 9d 99 e7 99 99 e7 98 99 e7 9b 99 e7 9a 5f ef 99 a6 }
    $xor_AA = { 20 e4 9e 9a e4 9a 9a e4 9b 9a e4 98 9a e4 99 5c ec 9a a5 }
    $xor_AB = { 21 e5 9f 9b e5 9b 9b e5 9a 9b e5 99 9b e5 98 5d ed 9b a4 }
    $xor_AC = { 26 e2 98 9c e2 9c 9c e2 9d 9c e2 9e 9c e2 9f 5a ea 9c a3 }
    $xor_AD = { 27 e3 99 9d e3 9d 9d e3 9c 9d e3 9f 9d e3 9e 5b eb 9d a2 }
    $xor_AE = { 24 e0 9a 9e e0 9e 9e e0 9f 9e e0 9c 9e e0 9d 58 e8 9e a1 }
    $xor_AF = { 25 e1 9b 9f e1 9f 9f e1 9e 9f e1 9d 9f e1 9c 59 e9 9f a0 }
    $xor_B0 = { 3a fe 84 80 fe 80 80 fe 81 80 fe 82 80 fe 83 46 f6 80 bf }
    $xor_B1 = { 3b ff 85 81 ff 81 81 ff 80 81 ff 83 81 ff 82 47 f7 81 be }
    $xor_B2 = { 38 fc 86 82 fc 82 82 fc 83 82 fc 80 82 fc 81 44 f4 82 bd }
    $xor_B3 = { 39 fd 87 83 fd 83 83 fd 82 83 fd 81 83 fd 80 45 f5 83 bc }
    $xor_B4 = { 3e fa 80 84 fa 84 84 fa 85 84 fa 86 84 fa 87 42 f2 84 bb }
    $xor_B5 = { 3f fb 81 85 fb 85 85 fb 84 85 fb 87 85 fb 86 43 f3 85 ba }
    $xor_B6 = { 3c f8 82 86 f8 86 86 f8 87 86 f8 84 86 f8 85 40 f0 86 b9 }
    $xor_B7 = { 3d f9 83 87 f9 87 87 f9 86 87 f9 85 87 f9 84 41 f1 87 b8 }
    $xor_B8 = { 32 f6 8c 88 f6 88 88 f6 89 88 f6 8a 88 f6 8b 4e fe 88 b7 }
    $xor_B9 = { 33 f7 8d 89 f7 89 89 f7 88 89 f7 8b 89 f7 8a 4f ff 89 b6 }
    $xor_BA = { 30 f4 8e 8a f4 8a 8a f4 8b 8a f4 88 8a f4 89 4c fc 8a b5 }
    $xor_BB = { 31 f5 8f 8b f5 8b 8b f5 8a 8b f5 89 8b f5 88 4d fd 8b b4 }
    $xor_BC = { 36 f2 88 8c f2 8c 8c f2 8d 8c f2 8e 8c f2 8f 4a fa 8c b3 }
    $xor_BD = { 37 f3 89 8d f3 8d 8d f3 8c 8d f3 8f 8d f3 8e 4b fb 8d b2 }
    $xor_BE = { 34 f0 8a 8e f0 8e 8e f0 8f 8e f0 8c 8e f0 8d 48 f8 8e b1 }
    $xor_BF = { 35 f1 8b 8f f1 8f 8f f1 8e 8f f1 8d 8f f1 8c 49 f9 8f b0 }
    $xor_C0 = { 4a 8e f4 f0 8e f0 f0 8e f1 f0 8e f2 f0 8e f3 36 86 f0 cf }
    $xor_C1 = { 4b 8f f5 f1 8f f1 f1 8f f0 f1 8f f3 f1 8f f2 37 87 f1 ce }
    $xor_C2 = { 48 8c f6 f2 8c f2 f2 8c f3 f2 8c f0 f2 8c f1 34 84 f2 cd }
    $xor_C3 = { 49 8d f7 f3 8d f3 f3 8d f2 f3 8d f1 f3 8d f0 35 85 f3 cc }
    $xor_C4 = { 4e 8a f0 f4 8a f4 f4 8a f5 f4 8a f6 f4 8a f7 32 82 f4 cb }
    $xor_C5 = { 4f 8b f1 f5 8b f5 f5 8b f4 f5 8b f7 f5 8b f6 33 83 f5 ca }
    $xor_C6 = { 4c 88 f2 f6 88 f6 f6 88 f7 f6 88 f4 f6 88 f5 30 80 f6 c9 }
    $xor_C7 = { 4d 89 f3 f7 89 f7 f7 89 f6 f7 89 f5 f7 89 f4 31 81 f7 c8 }
    $xor_C8 = { 42 86 fc f8 86 f8 f8 86 f9 f8 86 fa f8 86 fb 3e 8e f8 c7 }
    $xor_C9 = { 43 87 fd f9 87 f9 f9 87 f8 f9 87 fb f9 87 fa 3f 8f f9 c6 }
    $xor_CA = { 40 84 fe fa 84 fa fa 84 fb fa 84 f8 fa 84 f9 3c 8c fa c5 }
    $xor_CB = { 41 85 ff fb 85 fb fb 85 fa fb 85 f9 fb 85 f8 3d 8d fb c4 }
    $xor_CC = { 46 82 f8 fc 82 fc fc 82 fd fc 82 fe fc 82 ff 3a 8a fc c3 }
    $xor_CD = { 47 83 f9 fd 83 fd fd 83 fc fd 83 ff fd 83 fe 3b 8b fd c2 }
    $xor_CE = { 44 80 fa fe 80 fe fe 80 ff fe 80 fc fe 80 fd 38 88 fe c1 }
    $xor_CF = { 45 81 fb ff 81 ff ff 81 fe ff 81 fd ff 81 fc 39 89 ff c0 }
    $xor_D0 = { 5a 9e e4 e0 9e e0 e0 9e e1 e0 9e e2 e0 9e e3 26 96 e0 df }
    $xor_D1 = { 5b 9f e5 e1 9f e1 e1 9f e0 e1 9f e3 e1 9f e2 27 97 e1 de }
    $xor_D2 = { 58 9c e6 e2 9c e2 e2 9c e3 e2 9c e0 e2 9c e1 24 94 e2 dd }
    $xor_D3 = { 59 9d e7 e3 9d e3 e3 9d e2 e3 9d e1 e3 9d e0 25 95 e3 dc }
    $xor_D4 = { 5e 9a e0 e4 9a e4 e4 9a e5 e4 9a e6 e4 9a e7 22 92 e4 db }
    $xor_D5 = { 5f 9b e1 e5 9b e5 e5 9b e4 e5 9b e7 e5 9b e6 23 93 e5 da }
    $xor_D6 = { 5c 98 e2 e6 98 e6 e6 98 e7 e6 98 e4 e6 98 e5 20 90 e6 d9 }
    $xor_D7 = { 5d 99 e3 e7 99 e7 e7 99 e6 e7 99 e5 e7 99 e4 21 91 e7 d8 }
    $xor_D8 = { 52 96 ec e8 96 e8 e8 96 e9 e8 96 ea e8 96 eb 2e 9e e8 d7 }
    $xor_D9 = { 53 97 ed e9 97 e9 e9 97 e8 e9 97 eb e9 97 ea 2f 9f e9 d6 }
    $xor_DA = { 50 94 ee ea 94 ea ea 94 eb ea 94 e8 ea 94 e9 2c 9c ea d5 }
    $xor_DB = { 51 95 ef eb 95 eb eb 95 ea eb 95 e9 eb 95 e8 2d 9d eb d4 }
    $xor_DC = { 56 92 e8 ec 92 ec ec 92 ed ec 92 ee ec 92 ef 2a 9a ec d3 }
    $xor_DD = { 57 93 e9 ed 93 ed ed 93 ec ed 93 ef ed 93 ee 2b 9b ed d2 }
    $xor_DE = { 54 90 ea ee 90 ee ee 90 ef ee 90 ec ee 90 ed 28 98 ee d1 }
    $xor_DF = { 55 91 eb ef 91 ef ef 91 ee ef 91 ed ef 91 ec 29 99 ef d0 }
    $xor_E0 = { 6a ae d4 d0 ae d0 d0 ae d1 d0 ae d2 d0 ae d3 16 a6 d0 ef }
    $xor_E1 = { 6b af d5 d1 af d1 d1 af d0 d1 af d3 d1 af d2 17 a7 d1 ee }
    $xor_E2 = { 68 ac d6 d2 ac d2 d2 ac d3 d2 ac d0 d2 ac d1 14 a4 d2 ed }
    $xor_E3 = { 69 ad d7 d3 ad d3 d3 ad d2 d3 ad d1 d3 ad d0 15 a5 d3 ec }
    $xor_E4 = { 6e aa d0 d4 aa d4 d4 aa d5 d4 aa d6 d4 aa d7 12 a2 d4 eb }
    $xor_E5 = { 6f ab d1 d5 ab d5 d5 ab d4 d5 ab d7 d5 ab d6 13 a3 d5 ea }
    $xor_E6 = { 6c a8 d2 d6 a8 d6 d6 a8 d7 d6 a8 d4 d6 a8 d5 10 a0 d6 e9 }
    $xor_E7 = { 6d a9 d3 d7 a9 d7 d7 a9 d6 d7 a9 d5 d7 a9 d4 11 a1 d7 e8 }
    $xor_E8 = { 62 a6 dc d8 a6 d8 d8 a6 d9 d8 a6 da d8 a6 db 1e ae d8 e7 }
    $xor_E9 = { 63 a7 dd d9 a7 d9 d9 a7 d8 d9 a7 db d9 a7 da 1f af d9 e6 }
    $xor_EA = { 60 a4 de da a4 da da a4 db da a4 d8 da a4 d9 1c ac da e5 }
    $xor_EB = { 61 a5 df db a5 db db a5 da db a5 d9 db a5 d8 1d ad db e4 }
    $xor_EC = { 66 a2 d8 dc a2 dc dc a2 dd dc a2 de dc a2 df 1a aa dc e3 }
    $xor_ED = { 67 a3 d9 dd a3 dd dd a3 dc dd a3 df dd a3 de 1b ab dd e2 }
    $xor_EE = { 64 a0 da de a0 de de a0 df de a0 dc de a0 dd 18 a8 de e1 }
    $xor_EF = { 65 a1 db df a1 df df a1 de df a1 dd df a1 dc 19 a9 df e0 }
    $xor_F0 = { 7a be c4 c0 be c0 c0 be c1 c0 be c2 c0 be c3 06 b6 c0 ff }
    $xor_F1 = { 7b bf c5 c1 bf c1 c1 bf c0 c1 bf c3 c1 bf c2 07 b7 c1 fe }
    $xor_F2 = { 78 bc c6 c2 bc c2 c2 bc c3 c2 bc c0 c2 bc c1 04 b4 c2 fd }
    $xor_F3 = { 79 bd c7 c3 bd c3 c3 bd c2 c3 bd c1 c3 bd c0 05 b5 c3 fc }
    $xor_F4 = { 7e ba c0 c4 ba c4 c4 ba c5 c4 ba c6 c4 ba c7 02 b2 c4 fb }
    $xor_F5 = { 7f bb c1 c5 bb c5 c5 bb c4 c5 bb c7 c5 bb c6 03 b3 c5 fa }
    $xor_F6 = { 7c b8 c2 c6 b8 c6 c6 b8 c7 c6 b8 c4 c6 b8 c5 00 b0 c6 f9 }
    $xor_F7 = { 7d b9 c3 c7 b9 c7 c7 b9 c6 c7 b9 c5 c7 b9 c4 01 b1 c7 f8 }
    $xor_F8 = { 72 b6 cc c8 b6 c8 c8 b6 c9 c8 b6 ca c8 b6 cb 0e be c8 f7 }
    $xor_F9 = { 73 b7 cd c9 b7 c9 c9 b7 c8 c9 b7 cb c9 b7 ca 0f bf c9 f6 }
    $xor_FA = { 70 b4 ce ca b4 ca ca b4 cb ca b4 c8 ca b4 c9 0c bc ca f5 }
    $xor_FB = { 71 b5 cf cb b5 cb cb b5 ca cb b5 c9 cb b5 c8 0d bd cb f4 }
    $xor_FC = { 76 b2 c8 cc b2 cc cc b2 cd cc b2 ce cc b2 cf 0a ba cc f3 }
    $xor_FD = { 77 b3 c9 cd b3 cd cd b3 cc cd b3 cf cd b3 ce 0b bb cd f2 }
    $xor_FE = { 74 b0 ca ce b0 ce ce b0 cf ce b0 cc ce b0 cd 08 b8 ce f1 }
    $xor_FF = { 75 b1 cb cf b1 cf cf b1 ce cf b1 cd cf b1 cc 09 b9 cf f0 }


  condition:
    (uint16(0) == 0x5a4d) and any of them
}

rule malware_Lokibot_strings {
          meta:
            description = "detect Lokibot in memory"
            author = "JPCERT/CC Incident Response Group"
            rule_usage = "memory scan"
            reference = "internal research"
            hash1 = "6f12da360ee637a8eb075fb314e002e3833b52b155ad550811ee698b49f37e8c"

          strings:
            $des3 = { 68 03 66 00 00 }
            $param = "MAC=%02X%02X%02XINSTALL=%08X%08X"
            $string = { 2d 00 75 00 00 00 46 75 63 6b 61 76 2e 72 75 00 00}

          condition:
            all of them
}

rule malware_LuoYu_Stealer {
    meta:
      description = "detect LuoYu_Stealer"
      author = "JPCERT/CC Incident Response Group"
      hash1 = "d9df38fcd9fb557ff26c5950a1a7478226091cca7f17c65162f68e5feb6e2d8d"
      hash2 = "1e9fc7f32bd5522dd0222932eb9f1d8bd0a2e132c7b46cfcc622ad97831e6128"
      hash3 = "b9f526eea625eec1ddab25a0fc9bd847f37c9189750499c446471b7a52204d5a"
      hash4 = "0c365d9730a10f1a3680d24214682f79f88aa2a2a602d3d80ef4c1712210ab07"
      hash5 = "2eef273af0c768b514db6159d7772054d27a6fa8bc3d862df74de75741dbfb9c"

    strings:
      /* monitoring files */
      $str_m1 = "~B5D9" fullword ascii
      $str_m2 = "65ce-731bffbb" fullword ascii
      $str_m3 = "~BF24" fullword ascii
      $str_m4 = "~BF34" fullword ascii
      $str_m5 = "63ae-a20cf808" fullword ascii
      $str_m6 = "28e4-20a6acec" fullword ascii
      $str_m7 = "~FFFE" fullword ascii
      $str_m8 = "~B5BE" fullword ascii
      $str_m9 = "~B61A" fullword ascii
      $str_m10 = "d0c8-b9baa92f" fullword ascii
      $str_m11 = "~CE14" fullword ascii
      $str_m12 = "070a-cf37dcf5"  fullword ascii

      /* routine */
      $auth1 = {DB 70 20 24}
      $auth2 = {2A C6 87 47}
      $str_r1 = "Shell Folders" fullword ascii
      $str_r2 = "Common AppData" fullword ascii
      $str_r3 = "%s\\*.a" fullword ascii
      $str_r4 = "ackfile" fullword ascii
      $str_r5 = "YYYY" fullword ascii
      $str_r6 = "%s\\*.*" fullword ascii
      $str_r7 = "%s\\c25549fe" fullword ascii

    condition:
      ($str_m1 and $str_m2 and $str_m3 and $str_m4 and $str_m5 and $str_m6 and $str_m7 and $str_m8 and $str_m9 and $str_m10 and $str_m11 and $str_m12)
       or ($auth1 and $auth2 and $str_r1 and $str_r2 and $str_r3 and $str_r4 and $str_r5 and $str_r6 and $str_r7)
}

rule malware_Nanocore_strings {
          meta:
            description = "detect Nanocore in memory"
            author = "JPCERT/CC Incident Response Group"
            rule_usage = "memory scan"
            reference = "internal research"

          strings:
            $v1 = "NanoCore Client"
            $v2 = "PluginCommand"
            $v3 = "CommandType"

          condition:
            all of them
}

rule malware_netwire_strings {
           meta:
            description = "detect netwire in memory"
            author = "JPCERT/CC Incident Response Group"
            rule_usage = "memory scan"
            reference = "internal research"

          strings:
            $v1 = "HostId-%Rand%"
            $v2 = "mozsqlite3"
            $v3 = "[Scroll Lock]"
            $v4 = "GetRawInputData"
            $ping = "ping 192.0.2.2"
            $log = "[Log Started] - [%.2d/%.2d/%d %.2d:%.2d:%.2d]"

          condition:
            ($v1) or ($v2 and $v3 and $v4) or ($ping and $log)
}


rule malware_NimFilecoder {
    meta:
      description = "NimCopycatLoader malware in human-operated ransomware attack"
      author = "JPCERT/CC Incident Response Group"
      hash1 = "9a10ead4b8971b830daf1d0b7151462fb6cc379087b65b3013c756db3ce87118"

    strings:
      $str1 = ":wtfbbq" ascii wide
      $lib  = "clr.nim"  ascii wide

    condition:
      uint16(0) == 0x5A4D and all of them
}

rule malware_NimFilecoder02 {
    meta:
      description = "detect NimFilecoder"
      author = "JPCERT/CC Incident Response Group"
      rule_usage = "scan, hunt"
      hash1 = "9a10ead4b8971b830daf1d0b7151462fb6cc379087b65b3013c756db3ce87118"
      hash2 = "b6dc9052b9b1c23f90eb214336815e0df1bed8456f8aa5781dd0ec46bff42610"

    strings:
      /*  and    [reg], 55555555h    */
      $Func1 = { 81 E? 55 55 55 55 }
      /*  and    [reg], 0CCCCCCCCh    */
      $Func2 = { 81 E? CC CC CC CC }
      /*  and    [reg], 33333333h  */
      $Func3 = { 81 E? 33 33 33 33 }
      /*  and    [reg], 0F0F0F0Fh   */
      $Func4 = { 81 E? 0F 0F 0F 0F }
      /*  and    [reg], 0F0F0F0F0h   */
      $Func5 = { 81 E? F0 F0 F0 F0 }

      /* stirngs */
      $s0 = "io.nim" fullword ascii
      $s1 = "os.nim" fullword ascii
      $s2 = "fatal.nim" fullword ascii
      $s3 = "GetCommandLineW" fullword ascii
      $s4 = "PathFileExistsW" fullword ascii
      $s5 = "libgcc_s_dw2-1.dll" fullword ascii
      $s6 = "GetModuleFileNameW" fullword ascii
      $s7 = "IsEqualGUID" fullword ascii
      $s8 = "[GC] cannot register thread local variable" fullword ascii
      $s9 = "streams.nim" fullword ascii

    condition:
      uint16(0) == 0x5A4D and
      uint32(uint32(0x3c)) == 0x00004550 and
      all of them
}

rule malware_Njrat_strings {
          meta:
            description = "detect njRAT in memory"
            author = "JPCERT/CC Incident Response Group"
            rule_usage = "memory scan"
            hash1 = "d5f63213ce11798879520b0e9b0d1b68d55f7727758ec8c120e370699a41379d"

          strings:
            $reg = "SEE_MASK_NOZONECHECKS" wide fullword
            $msg = "Execute ERROR" wide fullword
            $ping = "cmd.exe /c ping 0 -n 2 & del" wide fullword
          condition:
            all of them
}

rule malware_Noderat_strings {
          meta:
            description = "detect Noderat in memory"
            author = "JPCERT/CC Incident Response Group"
            rule_usage = "memory scan"
            reference = "https://blogs.jpcert.or.jp/ja/2019/02/tick-activity.html"

          strings:
            $config = "/config/app.json"
            $key = "/config/.regeditKey.rc"
            $message = "uninstall error when readFileSync: "

          condition:
            all of them
}

rule webshell_phpfilemanager_str {
     meta:
        description = "Webshell PHP File Manager (2017-08-07)"
        author = "JPCERT/CC Incident Response Group"
        hash = "a8bd19d39700bce00fe7a525c551b04e36352d847e73c9741bb2816a3ea018df"

     strings:
        $str1 = "https://github.com/alexantr/filemanager"
        $str2 = "kbuvNx+mOcbN9taGBlpLAWf9nX8EGADoCfqkKWV/cgAAAABJRU5ErkJggg=="
        $str3 = "9oeiCT9Fr1cL/gmp125aUc4P+B85iX+qJ/la0k/Ze0D0T0j93jXTpv0BYUGhQhdSooYAAAAASUVO"
        $str4 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAEElEQVR42mL4//8/A0CAAQAI/AL+26JNFgAAAABJRU5ErkJggg=="
        $str5 = "iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAIAAACQkWg2AAAAKklEQVR42mL5//8/Azbw+PFjrOJMDCSCUQ3EABZc4S0rKzsaSvTTABBgAMyfCMsY4B9iAAAAAElFTkSuQmCC"

     condition:
       uint32(0) == 0x68703F3C and 3 of ($str*)
}

rule malware_lvscam_phpwebshell {
    meta:
        description = "PHP malware used in lucky visitor scam"
        author = "JPCERT/CC Incident Response Group"
        hash = "1c7fe8ee16da73a337c1502b1fe600462ce4b9a3220f923d02f900ea61c63020"
        hash = "aebeadc7a6c5b76d842c7852705152930c636866c7e6e5a9fa3be1c15433446c"

    strings:
        $s1 = "http://136.12.78.46/app/assets/api"
        $s2 = "['a'] == 'doorway2')"
        $s3 = "['sa'] == 'eval')"

    condition:
        2 of them
}

rule malware_PlugX_config {
          meta:
            description = "detect PlugX in memory"
            author = "JPCERT/CC Incident Response Group"
            rule_usage = "memory scan"
            reference = "internal research"

          strings:
            $v1 = { 47 55 4c 50 00 00 00 00 }
            $v2a = { 68 40 25 00 00 }
            $v2c = { 68 58 2D 00 00 }
            $v2b = { 68 a0 02 00 00 }
            $v2d = { 68 a4 36 00 00 }
            $v2e = { 8D 46 10 68 }
            $v2f = { 68 24 0D 00 00 }
            $v2g = { 68 a0 02 00 00 }
            $v2h = { 68 e4 0a 00 00 }
            $enc1 = { C1 E? 03 C1 E? 07 2B ?? }
            $enc2 = { 32 5? ?? 81 E? ?? ?? 00 00 2A 5? ?? 89 ?? ?? 32 ?? 2A ?? 32 5? ?? 2A 5? ?? 32 }
            $enc3 = { B? 33 33 33 33 }
            $enc4 = { B? 44 44 44 44 }

          condition:
            $v1 at 0 or ($v2a and $v2b and $enc1) or ($v2c and $v2b and $enc1) or ($v2d and $v2b and $enc2) or ($v2d and $v2e and $enc2) or ($v2f and $v2g and $enc3 and $enc4) or ($v2h and $v2g and $enc3 and $enc4)
}

rule malware_PoisonIvy {
           meta:
            description = "detect PoisonIvy in memory"
            author = "JPCERT/CC Incident Response Group"
            rule_usage = "memory scan"
            reference = "internal research"

          strings:
            $a1 = { 0E 89 02 44 }
            $b1 = { AD D1 34 41 }
            $c1 = { 66 35 20 83 66 81 F3 B8 ED }

          condition:
            all of them
}

rule malware_PSKiller_sys {
    meta:
      description = "detect PSKiller_sys Atom Silom and Rook"
      author = "JPCERT/CC Incident Response Group"
      hash1 = "f807699b6c71382c7d0da61d2becf29d1818483597213f2194bc00e63d47235e"
      hash2 = "c232b3d1ea2273b8ad827724c511d032cda7f2c66567638abf922a5d5287e388"

    strings:
      /* strings */
      $str01 = "hmpalert.exe" fullword ascii     
      $str02 = "savservice.exe" fullword ascii   
      $str03 = "savadminservice.exe" fullword ascii
      $str04 = "sophoscleanm64.exe" fullword ascii
      $str05 = "sdcservice.exe" fullword ascii   
      $str06 = "sophos ui.exe" fullword ascii    
      $str07 = "savapi.exe" fullword ascii       
      $str08 = "sedservice.exe" fullword ascii   
      $str09 = "sspservice.exe" fullword ascii   
      $str10 = "sophosfimservice.exe" fullword ascii
      $str11 = "sophosfilescanner.exe" fullword ascii
      $str12 = "sophosfs.exe" fullword ascii     
      $str13 = "sophoshealth.exe" fullword ascii 
      $str14 = "mcsagent.exe" fullword ascii     
      $str15 = "mcsclient.exe" fullword ascii    
      $str16 = "sophosntpservice.exe" fullword ascii
      $str17 = "sophossafestore64.exe" fullword ascii
      $str18 = "alsvc.exe" fullword ascii        
      $str19 = "swc_service.exe" fullword ascii  
      $str20 = "swi_fc.exe" fullword ascii       
      $str21 = "swi_filter.exe" fullword ascii   
      $str22 = "swi_service.exe" fullword ascii
      $str33 = "vmwp" fullword ascii
      $str34 = "virtualbox" fullword ascii
      $str35 = "vbox" fullword ascii
      $str36 = "sqlservr" fullword ascii
      $str37 = "mysqld" fullword ascii
      $str38 = "omtsreco" fullword ascii
      $str39 = "oracle" fullword ascii
      $str40 = "tnslsnr" fullword ascii
      $str41 = "vmware" fullword ascii
      $str42 = "sql.exe" fullword ascii
      $str43 = "oracle.exe" fullword ascii
      $str44 = "ocssd.exe" fullword ascii
      $str45 = "dbsnmp.exe" fullword ascii
      $str46 = "synctime.exe" fullword ascii
      $str47 = "agntsvc.exe" fullword ascii
      $str48 = "isqlplussvc.exe" fullword ascii
      $str49 = "xfssvccon.exe" fullword ascii
      $str51 = "mydesktopservice.exe" fullword ascii
      $str52 = "ocautoupds.exe" fullword ascii
      $str53 = "encsvc.exe" fullword ascii
      $str54 = "firefox.exe" fullword ascii
      $str55 = "tbirdconfig.exe" fullword ascii
      $str56 = "mydesktopqos.exe" fullword ascii
      $str57 = "ocomm.exe" fullword ascii
      $str58 = "dbeng50.exe" fullword ascii
      $str59 = "sqbcoreservice.exe" fullword ascii
      $str60 = "excel.exe" fullword ascii
      $str61 = "infopath.exe" fullword ascii
      $str62 = "msaccess.exe" fullword ascii
      $str63 = "mspub.exe" fullword ascii
      $str64 = "onenote.exe" fullword ascii
      $str65 = "outlook.exe" fullword ascii
      $str66 = "powerpnt.exe" fullword ascii
      $str67 = "steam.exe" fullword ascii
      $str68 = "thebat.exe" fullword ascii
      $str69 = "thunderbird.exe" fullword ascii
      $str70 = "visio.exe" fullword ascii
      $str71 = "winword.exe" fullword ascii
      $str72 = "wordpad.exe" fullword ascii
      $str73 = "notepad.exe" fullword ascii
      $str74 = "SmcGui.exe" fullword ascii
      $str75 = "SymCorpUI.exe" fullword ascii
      $str76 = "ccSvcHst.exe" fullword ascii
      $str77 = "sepWscSvc64.exe" fullword ascii
      $str78 = "PccNTMon.exe" fullword ascii
      $str79 = "CNTAoSMgr.exe" fullword ascii
      $str80 = "tmsainstance64.exe" fullword ascii
      $str81 = "tmlisten.exe" fullword ascii
      $str82 = "logserver.exe" fullword ascii
      $str83 = "ntrtscan.exe" fullword ascii
      $str84 = "tmccsf.exe" fullword ascii
      $str85 = "supportconnector.exe" fullword ascii
      $str86 = "tmwscsvc.exe" fullword ascii
      $str95 = "macmnsvc.exe" fullword ascii
      $str96 = "macompatsvc.exe" fullword ascii
      $str97 = "masvc.exe" fullword ascii
      $str98 = "mcshield.exe" fullword ascii
      $str99 = "mctray.exe" fullword ascii
      $str100 = "mfeatp.exe" fullword ascii
      $str101 = "mfecanary.exe" fullword ascii
      $str102 = "mfeensppl.exe" fullword ascii
      $str103 = "mfehcs.exe" fullword ascii
      $str104 = "mfemactl.exe" fullword ascii
      $str105 = "mfemms.exe" fullword ascii
      $str106 = "mfetp.exe" fullword ascii
      $str107 = "mfevtps.exe" fullword ascii
      $str108 = "mfewc.exe" fullword ascii
      $str109 = "mfewch.exe" fullword ascii
      $str110 = "mfewch.exe" fullword ascii
      $str111 = "ERAAgent.exe" fullword ascii
      $str112 = "ERAServer.exe" fullword ascii
      $str113 = "RDSensor.exe" fullword ascii
      $str114 = "eguiProxy.exe" fullword ascii
      $str115 = "egui.exe" fullword ascii
      $str116 = "entwine.exe" fullword ascii
      $str117 = "ekrn.exe" fullword ascii
      $str118 = "dsa.exe" fullword ascii
      $str119 = "Notifier.exe" fullword ascii
      $str120 = "coreFrameworkHost.exe" fullword ascii
      $str121 = "coreServiceShell.exe" fullword ascii
      $str122 = "RepUx.exe" fullword ascii
      $str123 = "scanhost.exe" fullword ascii
      $str124 = "RepUtils.exe" fullword ascii
      $str125 = "VHostComms.exe" fullword ascii

      /* API */
      $api1 = "PsGetProcessId" fullword ascii
      $api2 = "PsLookupProcessByProcessId" fullword ascii	  
      $api3 = "PsGetProcessImageFileName" fullword ascii
      $api4 = "_stricmp" fullword ascii
      $api5 = "ZwTerminateProcess" fullword ascii
      $api6 = "ZwClose" fullword ascii

    condition:
      (uint16(0) == 0x5A4D)
      and (filesize < 20KB)
      and (all of ($api*))
      and (20 of ($str*))
}

rule malware_pulsesecure_webshell {
     meta:
        description = "Webshell installed due to Pluse Connect Secure vulnerability(CVE-2021-22893)"
        author = "JPCERT/CC Incident Response Group"
        hash = "e3137135f4ad5ecdc7900a619d7f1b88ba252b963b38ae9a156299cc9bce92a1"
        hash = "0fe1758397e55084b05efcaeb056c10c7b991f6adbda10eee8c131b4b52f6534"
        hash = "1243b0bb3dc9ac428c76b57cf5f341923d49e35fcade0302c38d5d912d05fb7c"
        hash = "463023f0969b2b52bc491d8787de876e59f0d48446f908d16d1ce763bbe05ee9"

     strings:
        $webshellA1 = "Cache-Control: no-cache"
        $webshellA2 = "Content-type: text/html"
        $webshellA3 = "system("
        $webshellA4 = "if(CGI::param("
        $webshellA5 = "else{&main();}"
        $webshellB1 = "my $psalLaunch = CGI::param("
        $webshellB2 = "MIME::Base64::encode"
        $webshellB3 = "if ($psalLaunch ="
        $webshellB4 = "<button type=\"button\" onclick = \"submitData()\" >submit</botton>"
        $webshellB5 = "<input type=\"submit\" value=\"Run\">"
        $webshellB6 = "RC4($"
        $webshellB7 = "Could not execute command"
        $webshellC1 = "MIME::Base64::encode(RC4($"
        $webshellC2 = "Content-type:text/html"
        $webshellC3 = "HTTP_X_KEY"
        $webshellC4 = "HTTP_X_CMD"
        $webshellC5 = "HTTP_X_CNT"

     condition:
       all of ($webshellA*) or 4 of ($webshellB*) or all of ($webshellC*)
}

rule malware_QakBot {
    meta:
      description = "detect QakBot(a.k.a. Qbot, Quakbot, Pinkslipbot) in memory"
      author = "JPCERT/CC Incident Response Group"
      rule_usage = "memory scan"
      hash1 = "d766cd76c93dcc47d0d02e073216d792d1b377e31a4bae74969ab8076e286db3"
      hash2 = "717298e663d574444b63bb152063795326ac7c04edc9873a4ac2e407e1f550a1"

    strings:
      $cryptFunc1 = { 33 D2 6A ?? 5B F7 F3 }  /* xor edx, edx; push 5Ah; pop ebx; div ebx */
      $cryptFunc2 = { 32 04 37 } /* xor al, [edi+esi] */
      /*  .rdata:1001B258 dd 0, 1DB71064h, 3B6E20C8h, 26D930ACh
          .rdata:1001B258 dd 76DC4190h, 6B6B51F4h, 4DB26158h, 5005713Ch   */
      $hashFunc = { 64 10 B7 1D C8 20 6E 3B AC 30 D9 26  90 41 DC 76 F4 51 6B 6B}

    condition:
      uint16(0) == 0x5A4D and
      uint32(uint32(0x3c)) == 0x00004550 and 
      $cryptFunc1 and $cryptFunc2 and
      $hashFunc
}

rule malware_Quasar_strings {
          meta:
            description = "detect QuasarRAT in memory"
            author = "JPCERT/CC Incident Response Group"
            rule_usage = "memory scan"
            hash1 = "390c1530ff62d8f4eddff0ac13bc264cbf4183e7e3d6accf8f721ffc5250e724"

          strings:
            $quasarstr1 = "Client.exe" wide
            $quasarstr2 = "({0}:{1}:{2})" wide
            $sql1 = "SELECT * FROM Win32_DisplayConfiguration" wide
            $sql2 = "{0}d : {1}h : {2}m : {3}s" wide
            $sql3 = "SELECT * FROM FirewallProduct" wide
            $net1 = "echo DONT CLOSE THIS WINDOW!" wide
            $net2 = "freegeoip.net/xml/" wide
            $net3 = "http://api.ipify.org/" wide
            $resource = { 52 00 65 00 73 00 6F 00 75 00 72 00 63 00 65 00 73 00 00 17 69 00 6E 00 66 00 6F 00 72 00 6D 00 61 00 74 00 69 00 6F 00 6E 00 00 }

          condition:
            ((all of ($quasarstr*) or all of ($sql*)) and $resource) or all of ($net*)
}

rule malware_Remcos_strings {
          meta:
            description = "detect Remcos in memory"
            author = "JPCERT/CC Incident Response Group"
            rule_usage = "memory scan"
            hash1 = "7d5efb7e8b8947e5fe1fa12843a2faa0ebdfd7137582e5925a0b9c6a9350b0a5"

          strings:
            $remcos = "Remcos" ascii fullword
            $url1 = "Breaking-Security.Net" ascii fullword
            $url2 = "BreakingSecurity.Net" ascii fullword
            $resource = "SETTINGS" ascii wide fullword

          condition:
            1 of ($url*) and $remcos and $resource
}

rule malware_shellcode_hash {
    meta:
        description = "detect shellcode api hash value"
        author = "JPCERT/CC Incident Response Group"
        ref = "https://github.com/fireeye/flare-ida/blob/master/shellcode_hashes/sc_hashes.db"

    strings:
        $addRol5HashOncemore32_GetProcAddress = { 67 42 56 25 }
        $addRol5HashOncemore32_LoadLibraryA = { CC 70 77 6B }
        $imul21hAddHash32_GetProcAddress = { BF C1 CF DE }
        $imul21hAddHash32_LoadLibraryA = { DB 2F 07 B7 }
        $ror7AddHash32_GetProcAddress = { 85 DF AF BB }
        $ror7AddHash32_LoadLibraryA = { 32 74 91 0C }
        $shl7SubHash32DoublePulser_GetProcAddress = { B8 F8 FD 0A }
        $shl7SubHash32DoublePulser_LoadLibraryA = { 54 BE 48 01 }
        $imul83hAdd_GetProcAddress = { 54 B8 B9 1A }
        $imul83hAdd_LoadLibraryA = { 78 1F 20 7F }
        $xorShr8Hash32_GetProcAddress = { E5 52 D8 8D }
        $xorShr8Hash32_LoadLibraryA = { 31 7E EE 06 }
        $or23hXorRor17Hash32_GetProcAddress = { 33 00 A1 98 }
        $or23hXorRor17Hash32_LoadLibraryA = { 1F 0C B9 8E }
        $shl7Shr19XorHash32_GetProcAddress = { C8 FA C8 1B }
        $shl7Shr19XorHash32_LoadLibraryA = { 07 90 E4 63 }
        $rol3XorHash32_GetProcAddress = { 84 9B 50 F2 }
        $rol3XorHash32_LoadLibraryA = { 89 FD 12 A4 }
        $ror13AddHash32Sub20h_GetProcAddress = { 7A EE CA 1A }
        $ror13AddHash32Sub20h_LoadLibraryA = { 76 46 8B 8A }
        $crc32_GetProcAddress = { FF 1F 7C C9 }
        $crc32_LoadLibraryA = { 8D BD C1 3F }
        $chAddRol8Hash32_GetProcAddress = { 11 78 32 28 }
        $chAddRol8Hash32_LoadLibraryA = { 41 5F 59 35 }
        $ror13AddHash32Dll_GetProcAddress = { 49 F7 02 78 }
        $ror13AddHash32Dll_LoadLibraryA = { 4C 77 26 07 }
        $playWith0xedb88320Hash_GetProcAddress = { FF 1F 7C C9 }
        $playWith0xedb88320Hash_LoadLibraryA = { 8D BD C1 3F }
        $rol9AddHash32_GetProcAddress = { 89 2F AC 6B }
        $rol9AddHash32_LoadLibraryA = { EB 9F D7 E0 }
        $crc32_bzip2_GetProcAddress = { 92 A8 C4 0D }
        $crc32_bzip2_LoadLibraryA = { CB 8C AA 7A }
        $ror9AddHash32_GetProcAddress = { 8E 9F 45 72 }
        $ror9AddHash32_LoadLibraryA = { CA CC DE 43 }
        $ror11AddHash32_GetProcAddress = { D0 05 89 E9 }
        $ror11AddHash32_LoadLibraryA = { 97 16 5F FA }
        $rol7AddHash32_GetProcAddress = { 54 15 7F FC }
        $rol7AddHash32_LoadLibraryA = { C9 FF DF 10 }
        $ror13AddHash32_GetProcAddress = { AA FC 0D 7C }
        $ror13AddHash32_LoadLibraryA = { 8E 4E 0E EC }
        $ror13AddHash32Sub1_GetProcAddress = { A9 FC 0D 7C }
        $ror13AddHash32Sub1_LoadLibraryA = { 8D 4E 0E EC }
        $rol3XorEax_GetProcAddress = { 08 EE 31 9C }
        $rol3XorEax_LoadLibraryA = { FB 32 8C AE }
        $xorRol9Hash32_GetProcAddress = { 93 40 B9 B4 }
        $xorRol9Hash32_LoadLibraryA = { 5E 4B A6 8D }
        $rol9XorHash32_GetProcAddress = { A0 5C DA 49 }
        $rol9XorHash32_LoadLibraryA = { 25 D3 46 AF }
        $rol5AddHash32_GetProcAddress = { 90 55 C9 99 }
        $rol5AddHash32_LoadLibraryA = { DC DD 1A 33 }
        $poisonIvyHash_GetProcAddress = { 1F 7C C9 FF }
        $poisonIvyHash_LoadLibraryA = { AD D1 34 41 }
        $rol7XorHash32_GetProcAddress = { EE EA C0 1F }
        $rol7XorHash32_LoadLibraryA = { 26 80 AC C8 }
        $crc32Xor0xca9d4d4e_GetProcAddress = { B1 52 E1 03 }
        $crc32Xor0xca9d4d4e_LoadLibraryA = { C3 F0 5C F5 }
        $playWith0xe8677835Hash_GetProcAddress = { 54 EF 20 A1 }
        $playWith0xe8677835Hash_LoadLibraryA = { D1 18 AC A7 }
        $addRor13HashOncemore32_GetProcAddress = { 9F 2A 7F 03 }
        $addRor13HashOncemore32_LoadLibraryA = { BB A3 93 03 }
        $shl7Shr19AddHash32_GetProcAddress = { 54 15 7F FC }
        $shl7Shr19AddHash32_LoadLibraryA = { C9 FF DF 10 }
        $or21hXorRor11Hash32_GetProcAddress = { 77 CD 66 33 }
        $or21hXorRor11Hash32_LoadLibraryA = { 92 7C D0 94 }
        $or60hAddShl1Hash32_GetProcAddress = { FA 8B 34 00 }
        $or60hAddShl1Hash32_LoadLibraryA = { 86 57 0D 00 }
        $addRor13Hash32_GetProcAddress = { 6F E0 53 E5 }
        $addRor13Hash32_LoadLibraryA = { 72 60 77 74 }
        $rol8Xor0xB0D4D06Hash32_GetProcAddress = { 43 50 0F 5F }
        $rol8Xor0xB0D4D06Hash32_LoadLibraryA = { 47 1A 57 5F }
        $ror13AddHash32DllSimple_GetProcAddress = { C1 C6 39 EA }
        $ror13AddHash32DllSimple_LoadLibraryA = { A5 18 3A 5A }
        $shr2Shl5XorHash32_GetProcAddress = { AF 34 50 93 }
        $shr2Shl5XorHash32_LoadLibraryA = { 5B 75 8A F0 }
        $rol5XorHash32_GetProcAddress = { DB B6 B6 E5 }
        $rol5XorHash32_LoadLibraryA = { 3B 00 A1 B4 }

    condition:
        all of ($addRol5HashOncemore32*) or
        all of ($imul21hAddHash32*) or
        all of ($ror7AddHash32*) or
        all of ($shl7SubHash32DoublePulser*) or
        all of ($imul83hAdd*) or
        all of ($xorShr8Hash32*) or
        all of ($or23hXorRor17Hash32*) or
        all of ($shl7Shr19XorHash32*) or
        all of ($rol3XorHash32*) or
        all of ($ror13AddHash32Sub20h*) or
        all of ($crc32*) or
        all of ($chAddRol8Hash32*) or
        all of ($ror13AddHash32Dll*) or
        all of ($playWith0xedb88320Hash*) or
        all of ($rol9AddHash32*) or
        all of ($crc32_bzip2*) or
        all of ($ror9AddHash32*) or
        all of ($ror11AddHash32*) or
        all of ($rol7AddHash32*) or
        all of ($ror13AddHash32*) or
        all of ($ror13AddHash32Sub1*) or
        all of ($rol3XorEax*) or
        all of ($xorRol9Hash32*) or
        all of ($rol9XorHash32*) or
        all of ($rol5AddHash32*) or
        all of ($poisonIvyHash*) or
        all of ($rol7XorHash32*) or
        all of ($crc32Xor0xca9d4d4e*) or
        all of ($playWith0xe8677835Hash*) or
        all of ($addRor13HashOncemore32*) or
        all of ($shl7Shr19AddHash32*) or
        all of ($or21hXorRor11Hash32*) or
        all of ($or60hAddShl1Hash32*) or
        all of ($addRor13Hash32*) or
        all of ($rol8Xor0xB0D4D06Hash32*) or
        all of ($ror13AddHash32DllSimple*) or
        all of ($shr2Shl5XorHash32*) or
        all of ($rol5XorHash32*)
}

rule malware_SmokeLoader {
          meta:
            description = "detect SmokeLoader in memory"
            author = "JPCERT/CC Incident Response Group"
            rule_usage = "memory scan"
            reference = "https://www.cert.pl/en/news/single/dissecting-smoke-loader/"

          strings:
            $a1 = { B8 25 30 38 58 }
            $b1 = { 81 3D ?? ?? ?? ?? 25 00 41 00 }
            $c1 = { C7 ?? ?? ?? 25 73 25 73 }

          condition:
            $a1 and $b1 and $c1
}

rule malware_StealthWorker {
    meta:
      description = "detect StealthWorker"
      author = "JPCERT/CC Incident Response Group"
      hash1 = "b6fc97981b4be0536b650a364421d1435609223e1c5a058edeced954ca25f6d1"

    strings:
      $a1 = "StealthWorker/Worker"
      $a2 = "/bots/knock?worker=%s&os=%s&version=%s"
      $a3 = "/project/saveGood"

    condition:
      all of them
}

rule malware_SysrvBot {
    meta:
      description = "detect SysrvBot"
      author = "JPCERT/CC Incident Response Group"
      hash1 = "9df43de4920699bd51d4964b681bd2ce8315b189b812f92084f7c3e423610b2f"
      hash2 = "506d0ed05c5334cf4461380123eab85e46398220ed82386745f3d8ef3339adf9"

    strings:
      $a1 = "hello/controller/xmrig"
      $a2 = "hello/scan.(*Scanner)."
      $a3 = "hello/exp/exploit.go"

    condition:
      all of them
}

rule malware_TokyoX_Loader {
    meta:
        description = "detect TokyoX Loader"
        author = "JPCERT/CC Incident Response Group"
        hash = "382b3d3bb1be4f14dbc1e82a34946a52795288867ed86c6c43e4f981729be4fc"

    strings:
        $str =  "NtAllocateVirtuaNtWriteVirtualMeNtCreateThreadEx"

    condition:
        (uint16(0) == 0x5A4D) and all of them
}

rule malware_TokyoX_RAT {
    meta:
        description = "detect TokyoX RAT"
        author = "JPCERT/CC Incident Response Group"
        hash = "46bf7ca79cd21289081e518a7b3bc310bbfafc558eb3356b987319fec4d15939"

    strings:
        $mz = { 74 6F 6B 79 6F 00 00 00 } // tokyo
        $pe = "PE"
        $format1 = "%08lX%04lX%04lX%02lx%02lx%02lx%02lx%02lx%02lx%02lx%02lx"
        $format2 = "%d-%d-%d %d:%d:%d" wide
        $uniq_path = "C:\\Windows\\SysteSOFTWARE\\Microsoft\\Windows NT\\Cu"

    condition:
        ($mz at 0 and $pe in (0x0..0x200)) or all of ($format*) or $uniq_path
}

rule malware_Ursnif_strings {
          meta:
            description = "detect Ursnif(a.k.a. Dreambot, Gozi, ISFB) in memory"
            author = "JPCERT/CC Incident Response Group"
            rule_usage = "memory scan"
            reference = "internal research"
            hash1 = "0207c06879fb4a2ddaffecc3a6713f2605cbdd90fc238da9845e88ff6aef3f85"
            hash2 = "ff2aa9bd3b9b3525bae0832d1e2b7c6dfb988dc7add310088609872ad9a7e714"
            hash3 = "1eca399763808be89d2e58e1b5e242324d60e16c0f3b5012b0070499ab482510"

          strings:
            $a1 = "soft=%u&version=%u&user=%08x%08x%08x%08x&server=%u&id=%u&crc=%x"
            $b1 = "client.dll" fullword
            $c1 = "version=%u"
            $c2 = "user=%08x%08x%08x%08x"
            $c3 = "server=%u"
            $c4 = "id=%u"
            $c5 = "crc=%u"
            $c6 = "guid=%08x%08x%08x%08x"
            $c7 = "name=%s"
            $c8 = "soft=%u"
            $d1 = "%s://%s%s"
            $d2 = "PRI \x2A HTTP/2.0"
            $e1 = { A1 ?? ?? ?? 00 35 E7 F7 8A 40 50 }
            $e2 = { 56 56 56 6A 06 5? FF ?? ?? ?? ?? 00 }
            $f1 = { 56 57 BE ?? ?? ?? ?? 8D ?? ?? A5 A5 A5 }
            $f2 = { 35 8F E3 B7 3F }
            $f3 = { 35 0A 60 2E 51 }

          condition:
            $a1 or ($b1 and 3 of ($c*)) or (5 of ($c*)) or ($b1 and all of ($d*)) or all of ($e*) or all of ($f*)
}

rule WaterPamola_eccube_injection {
     meta:
        description = "Water Pamola EC-CUBE injection script"
        author = "JPCERT/CC Incident Response Group"
        hash = "ab0b1dd012907aad8947dd89d66d5844db781955234bb0ba7ef9a4e0a6714b3a"

     strings:
        $code1 = "eval(function(p,a,c,k," ascii
        $code2 = "Bootstrap v3.3.4 (http://getbootstrap.com)" ascii
        $code3 = "https://gist.github.com/a36e28ee268bb8a3c6c2" ascii

     condition:
        all of them
}

rule WaterPamola_webshell_str {
     meta:
        description = "Chainese webshell using water pamola"
        author = "JPCERT/CC Incident Response Group"
        hash = "a619f1ff0c6a5c8fc26871b9c0492ca331a9f84c66fa7479d0069b7e3b22ba31"

     strings:
        $str1 = "$password"
        $str2 = "$register_key"
        $str3 = "$check_copyright"
        $str4 = "$global_version"
        $str5 = "Language and charset conversion settings"
        $str6 = "This is a necessary key"

     condition:
       uint32(0) == 0x68703F3C and all of them
}

rule WaterPamola_stealjs_str {
     meta:
        description = "Injection code from xss using water pamola"
        author = "JPCERT/CC Incident Response Group"
        hash = "af99c566c94366f0f172475feedeeaab87177e102c28e703c1f0eeb6f41a835e"

     strings:
        $str1 = "getSou("
        $str2 = "eval(function(p,a,c,k,"
        $str3 = "poRec"
        $str4 = "application/x-www-form-urlencoded"
        $str5 = "XMLHttpRequest"
        $str6 = "device_type_id"
        $str7 = "ownersstore"
        $str8 = "transactionid"
        $str9 = "admin_template"
        $str10 = "ec_ver"

     condition:
       6 of ($str*)
}

rule WaterPamola_webshell_eval {
     meta:
        description = "WaterPamola eval webshell"
        author = "JPCERT/CC Incident Response Group"
        hash = "9fc3b3e59fbded4329a9401855d2576a1f2d76c429a0b9c8ea7c9752cd7e8378"

     strings:
        $encode1 = "IEBldmF"
        $encode2 = "F6ciddKTs="
        $encode3 = "CRfUE9TVF"
        $str1 = "@package Page"
        $str2 = " str_replace"
        $str3 = "$vbl"

     condition:
        uint32(0) == 0x68703F3C and 4 of them
}

rule malware_WinDealer {
    meta:
      description = "detect WinDealer LuoYu"
      author = "JPCERT/CC Incident Response Group"
      hash2 = "1e9fc7f32bd5522dd0222932eb9f1d8bd0a2e132c7b46cfcc622ad97831e6128"
      hash3 = "b9f526eea625eec1ddab25a0fc9bd847f37c9189750499c446471b7a52204d5a"
      hash4 = "0c365d9730a10f1a3680d24214682f79f88aa2a2a602d3d80ef4c1712210ab07"
      hash5 = "2eef273af0c768b514db6159d7772054d27a6fa8bc3d862df74de75741dbfb9c"

    strings:
      /* monitoring files */
      $moni_1 = "~B5D9" fullword ascii
      $moni_2 = "65ce-731bffbb" fullword ascii
      $moni_3 = "~BF24" fullword ascii
      $moni_4 = "~BF34" fullword ascii
      $moni_5 = "63ae-a20cf808" fullword ascii
      $moni_6 = "28e4-20a6acec" fullword ascii
      $moni_7 = "~FFFE" fullword ascii
      $moni_8 = "~B5BE" fullword ascii
      $moni_9 = "~B61A" fullword ascii
      $moni_10 = "d0c8-b9baa92f" fullword ascii
      $moni_11 = "~CE14" fullword ascii
      $moni_12 = "070a-cf37dcf5"  fullword ascii

      /* code, strings */
      $auth1 = {DB 70 20 24}
      $auth2 = {2A C6 87 47}
      $str_1 = "Shell Folders" fullword ascii
      $str_2 = "Common AppData" fullword ascii
      $str_3 = "%s\\*.a" fullword ascii
      $str_4 = "ackfile" fullword ascii
      $str_5 = "YYYY" fullword ascii
      $str_6 = "%s\\*.*" fullword ascii
      $str_7 = "%s\\c25549fe" fullword ascii

    condition:
	  (uint16(0) == 0x5A4D)
	  and (filesize < 3MB)
	  and (8 of ($moni_*))
	  and (all of ($auth*))
      and (5 of ($str_*))
}