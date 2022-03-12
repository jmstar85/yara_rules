import "pe"
import "hash"
import "math"

rule CISA_crypt_constants_2 
{ 
   meta: 
      Author="NCCIC trusted 3rd party" 
      Incident="10135536" 
      Date = "2018/04/19" 
      category = "hidden_cobra" 
      family = "n/a" 
      description = "n/a"   
   strings: 
      $ = {efcdab90} 
      $ = {558426fe} 
      $ = {7856b4c2} 
   condition: 
      (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) and all of them 
}

rule CISA_lsfr_constants 
{ 
   meta: 
      Author="NCCIC trusted 3rd party" 
      Incident="10135536" 
      Date = "2018/04/19" 
      category = "hidden_cobra" 
      family = "n/a" 
      description = "n/a" 
   strings: 
      $ = {efcdab90} 
      $ = {558426fe} 
      $ = {7856b4c2} 
   condition: 
      (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) and all of them 
}

rule CISA_polarSSL_servernames 
{ 
   meta: 
      Author="NCCIC trusted 3rd party" 
      Incident="10135536" 
      Date = "2018/04/19" 
      category = "hidden_cobra" 
      family = "n/a" 
      description = "n/a" 
   strings: 
      $polarSSL = "fjiejffndxklfsdkfjsaadiepwn" 
      $sn1 = "www.google.com" 
      $sn2 = "www.naver.com" 
   condition: 
      (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) -- 0x4550) and ($polarSSL and 1 of ($sn*))
}

rule CISA_10318927_01 : trojan rat SOLAR_FIRE
{
   meta:
       Author = "CISA Code & Media Analysis"
       Incident = "10318927"
       Date = "2020-12-13"
       Last_Modified = "20201213_2145"
       Actor = "n/a"
       Category = "TROJAN RAT"
       Family = "SOLAR_FIRE"
       Description = "This signature is based off of unique strings embedded within the modified Solar Winds app"
       MD5_1 = "b91ce2fa41029f6955bff20079468448"
       SHA256_1 = "32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77"
       MD5_2 = "846e27a652a5e1bfbd0ddd38a16dc865"
       SHA256_2 = "ce77d116a074dab7a22a0fd4f2c1ab475f16eec42e1ded3c0b0aa8211fe858d6"
   strings:
       $s0 = { 63 00 30 00 6B 00 74 00 54 00 69 00 37 00 4B 00 4C 00 43 00 6A 00 4A 00 7A 00 4D 00 38 00 44 }
       $s1 = { 41 00 41 00 3D 00 3D 00 00 21 38 00 33 00 56 00 30 00 64 00 6B 00 78 00 4A 00 4B 00 55 }
       $s2 = { 63 00 2F 00 46 00 77 00 44 00 6E 00 44 00 4E 00 53 00 30 00 7A 00 4B 00 53 00 55 00 30 00 42 00 41 00 41 00 3D 00 3D }
       $s3 = { 53 00 69 00 30 00 75 00 42 00 67 00 41 00 3D 00 00 21 38 00 77 00 77 00 49 00 4C 00 6B 00 33 00 4B 00 53 00 79 00 30 00 42 }
   condition:
all of them
}
rule CISA_FireEye_20_00025668_01 : SUNBURST APT backdoor
{
   meta:
       Author = "FireEye"
       Date = "2020-12-13"
       Last_Modified = "20201213_1917"
       Actor = "n/a"
       Category = "Backdoor"
       Family = "SUNBURST"
       Description = "This rule is looking for portions of the SUNBURST backdoor that are vital to how it functions. The first signature fnv_xor matches a magic byte xor that the sample performs on process, service, and driver names/paths. SUNBURST is a backdoor that has the ability to spawn and kill processes, write and delete files, set and create registry keys, gather system information, and disable a set of forensic analysis tools and services."
       MD5_1 = ""
       SHA256_1 = ""
   strings:
       $cmd_regex_encoded = "U4qpjjbQtUzUTdONrTY2q42pVapRgooABYxQuIZmtUoA" wide
       $cmd_regex_plain = { 5C 7B 5B 30 2D 39 61 2D 66 2D 5D 7B 33 36 7D 5C 7D 22 7C 22 5B 30 2D 39 61 2D 66 5D 7B 33 32 7D 22 7C 22 5B 30 2D 39 61 2D 66 5D 7B 31 36 7D }
       $fake_orion_event_encoded = "U3ItS80rCaksSFWyUvIvyszPU9IBAA==" wide
       $fake_orion_event_plain = { 22 45 76 65 6E 74 54 79 70 65 22 3A 22 4F 72 69 6F 6E 22 2C }
       $fake_orion_eventmanager_encoded = "U3ItS80r8UvMTVWyUgKzfRPzEtNTi5R0AA==" wide
       $fake_orion_eventmanager_plain = { 22 45 76 65 6E 74 4E 61 6D 65 22 3A 22 45 76 65 6E 74 4D 61 6E 61 67 65 72 22 2C }
       $fake_orion_message_encoded = "U/JNLS5OTE9VslKqNqhVAgA=" wide
       $fake_orion_message_plain = { 22 4D 65 73 73 61 67 65 22 3A 22 7B 30 7D 22 }
       $fnv_xor = { 67 19 D8 A7 3B 90 AC 5B }
   condition:
       $fnv_xor and ($cmd_regex_encoded or $cmd_regex_plain) or ( ($fake_orion_event_encoded or $fake_orion_event_plain) and ($fake_orion_eventmanager_encoded or $fake_orion_eventmanager_plain) and ($fake_orion_message_encoded and $fake_orion_message_plain) )
}

rule CISA_FireEye_20_00025668_02 : SUNBURST APT backdoor
{
   meta:
       Author = "FireEye"
       Date = "2020-12-13"
       Last_Modified = "20201213_1917"
       Actor = "n/a"
       Category = "Backdoor"
       Family = "SUNBURST"
       Description = "The SUNBURST backdoor uses a domain generation algorithm (DGA) as part of C2 communications. This rule is looking for each branch of the code that checks for which HTTP method is being used. This is in one large conjunction, and all branches are then tied together via disjunction. The grouping is intentionally designed so that if any part of the DGA is re-used in another sample, this signature should match that re-used portion. SUNBURST is a backdoor that has the ability to spawn and kill processes, write and delete files, set and create registry keys, gather system information, and disable a set of forensic analysis tools and services."
       MD5_1 = ""
       SHA256_1 = ""
   strings:
       $a = "0y3Kzy8BAA==" wide
       $aa = "S8vPKynWL89PS9OvNqjVrTYEYqNa3fLUpDSgTLVxrR5IzggA" wide
       $ab = "S8vPKynWL89PS9OvNqjVrTYEYqPaauNaPZCYEQA=" wide
       $ac = "C88sSs1JLS4GAA==" wide
       $ad = "C/UEAA==" wide
       $ae = "C89MSU8tKQYA" wide
       $af = "8wvwBQA=" wide
       $ag = "cyzIz8nJBwA=" wide
       $ah = "c87JL03xzc/LLMkvysxLBwA=" wide
       $ai = "88tPSS0GAA==" wide
       $aj = "C8vPKc1NLQYA" wide
       $ak = "88wrSS1KS0xOLQYA" wide
       $al = "c87PLcjPS80rKQYA" wide
       $am = "Ky7PLNAvLUjRBwA=" wide
       $an = "06vIzQEA" wide
       $b = "0y3NyyxLLSpOzIlPTgQA" wide
       $c = "001OBAA=" wide
       $d = "0y0oysxNLKqMT04EAA==" wide
       $e = "0y3JzE0tLknMLQAA" wide
       $f = "003PyU9KzAEA" wide
       $h = "0y1OTS4tSk1OBAA=" wide
       $i = "K8jO1E8uytGvNqitNqytNqrVA/IA" wide
       $j = "c8rPSQEA" wide
       $k = "c8rPSfEsSczJTAYA" wide
       $l = "c60oKUp0ys9JAQA=" wide
       $m = "c60oKUp0ys9J8SxJzMlMBgA=" wide
       $n = "8yxJzMlMBgA=" wide
       $o = "88lMzygBAA==" wide
       $p = "88lMzyjxLEnMyUwGAA==" wide
       $q = "C0pNL81JLAIA" wide
       $r = "C07NzXTKz0kBAA==" wide
       $s = "C07NzXTKz0nxLEnMyUwGAA==" wide
       $t = "yy9IzStOzCsGAA==" wide
       $u = "y8svyQcA" wide
       $v = "SytKTU3LzysBAA==" wide
       $w = "C84vLUpOdc5PSQ0oygcA" wide
       $x = "C84vLUpODU4tykwLKMoHAA==" wide
       $y = "C84vLUpO9UjMC07MKwYA" wide
       $z = "C84vLUpO9UjMC04tykwDAA==" wide
   condition:
       ($a and $b and $c and $d and $e and $f and $h and $i) or ($j and $k and $l and $m and $n and $o and $p and $q and $r and $s and ($aa or $ab)) or ($t and $u and $v and $w and $x and $y and $z and ($aa or $ab)) or ($ac and $ad and $ae and $af and $ag and $ah and ($am or $an)) or ($ai and $aj and $ak and $al and ($am or $an))
}


rule CISA_10320115_01 : TEARDROP trojan backdoor
{
   meta:
       Author = "CISA Code & Media Analysis"
       Incident = "10320115"
       Date = "2020-12-31"
       Last_Modified = "20201231_1800"
       Actor = "n/a"
       Category = "Trojan Backdoor"
       Family = "TEARDROP"
       Description = "Detects variants of TEARDROP malware"
       MD5_1 = "f612bce839d855bbff98214a197489f7"
       SHA256_1 = "dc20f4e50784533d7d10925e4b056f589cc73c139e97f40c0b7969728a28125c"
       MD5_2 = "91e47c7bc9a7809e6b1560e34f2d6d7e"
       SHA256_2 = "b37007db21a7f969d2c838f3bbbeb78a7402d66735bb5845ef31df9048cc33f0"
       MD5_3 = "91e47c7bc9a7809e6b1560e34f2d6d7e"
       SHA256_3 = "1817a5bf9c01035bcf8a975c9f1d94b0ce7f6a200339485d8f93859f8f6d730c"    
   strings:
       $s0 = { 65 23 FB 7F 20 AA EB 0C B8 16 F6 BC 2F 4D D4 C4 39 97 C7 23 9F 3E 5C DE }
       $s1 = { 5C E6 06 63 FA DE 44 C0 D4 67 95 28 12 47 C5 B5 EF 24 BC E4 }
       $s2 = { 9E 96 BA 1B FB 7F 19 5A 8C 06 AB FA 43 3B F0 83 9E 54 0B 02 }
       $s3 = { C2 7E 93 FC 02 B9 C6 DE 2B AF C6 C2 BE 2C 88 02 B4 1D 03 F5 }
       $s4 = { 48 B8 53 4F 46 54 57 41 52 45 C7 44 24 60 66 74 5C 43 C6 44 24 66 00 48 89 44 24 50 48 B8 5C 4D 69 63 72 6F 73 6F }
       $s5 = { 48 83 F8 FF 48 8D }
       $s6 = { 8B 0A 48 83 C2 04 8D 81 FF FE FE FE F7 D1 21 C8 25 80 80 80 80 }
       $s7 = { 5B 5E 5F 5D 41 5C 41 }
       $s8 = { 4E 00 65 00 74 00 77 00 6F 00 72 00 6B 00 20 00 53 00 65 00 74 00 75 00 70 00 20 00 53 00 65 00 72 00 76 00 69 00 63 00 65 }
       $s9 = { 64 6C 6C 00 4E 65 74 53 65 74 75 70 53 65 72 76 69 63 65 4D 61 69 6E }
       $s10 = { 41 31 C0 45 88 04 0A 48 83 C1 01 45 89 C8 41 39 CB 7F }
   condition:
       ($s0 or $s1 or $s2 or $s3) or ($s4 and $s5 and $s6 and $s7 and $s8 and $s9 and $s10)
}
rule CISA_FireEye_20_00025665_01 : TEARDROP APT dropper
{
   meta:
       Author = "FireEye"
       Date = "2020-12-13"
       Last_Modified = "20201213_1916"
       Actor = "n/a"
       Category = "Hacktool"
       Family = "TEARDROP"
       Description = "This rule looks for portions of the TEARDROP backdoor that are vital to how it functions. TEARDROP is a memory only dropper that can read files and registry keys, XOR decode an embedded payload, and load the payload into memory. TEARDROP persists as a Windows service and has been observed dropping Cobalt Strike BEACON into memory."
       MD5_1 = ""
       SHA256_1 = ""
   strings:
       $sb1 = { C7 44 24 ?? 80 00 00 00 [0-64] BA 00 00 00 80 [0-32] 48 8D 0D [4-32] FF 15 [4] 48 83 F8 FF [2-64] 41 B8 40 00 00 00 [0-64] FF 15 [4-5] 85 C0 7? ?? 80 3D [4] FF }
       $sb2 = { 80 3D [4] D8 [2-32] 41 B8 04 00 00 00 [0-32] C7 44 24 ?? 4A 46 49 46 [0-32] E8 [4-5] 85 C0 [2-32] C6 05 [4] 6A C6 05 [4] 70 C6 05 [4] 65 C6 05 [4] 67 }
       $sb3 = { BA [4] 48 89 ?? E8 [4] 41 B8 [4] 48 89 ?? 48 89 ?? E8 [4] 85 C0 7? [1-32] 8B 44 24 ?? 48 8B ?? 24 [1-16] 48 01 C8 [0-32] FF D0 }
   condition:
       all of them
}
rule CISA_FireEye_20_00025665_02 : TEARDROP APT dropper
{
   meta:
       Author = "FireEye"
       Date = "2020-12-13"
       Last_Modified = "20201213_1916"
       Actor = "n/a"
       Category = "Hacktool"
       Family = "TEARDROP"
       Description = "This rule is intended match specific sequences of opcode found within TEARDROP, including those that decode the embedded payload. TEARDROP is a memory only dropper that can read files and registry keys, XOR decode an embedded payload, and load the payload into memory. TEARDROP persists as a Windows service and has been observed dropping Cobalt Strike BEACON into memory."
       MD5_1 = ""
       SHA256_1 = ""
   strings:
       $loc_4218FE24A5 = { 48 89 C8 45 0F B6 4C 0A 30 }
       $loc_4218FE36CA = { 48 C1 E0 04 83 C3 01 48 01 E8 8B 48 28 8B 50 30 44 8B 40 2C 48 01 F1 4C 01 FA }
       $loc_4218FE2747 = { C6 05 ?? ?? ?? ?? 6A C6 05 ?? ?? ?? ?? 70 C6 05 ?? ?? ?? ?? 65 C6 05 ?? ?? ?? ?? 67 }
       $loc_5551D725A0 = { 48 89 C8 45 0F B6 4C 0A 30 48 89 CE 44 89 CF 48 F7 E3 48 C1 EA 05 48 8D 04 92 48 8D 04 42 48 C1 E0 04 48 29 C6 }
       $loc_5551D726F6 = { 53 4F 46 54 57 41 52 45 ?? ?? ?? ?? 66 74 5C 43 ?? ?? ?? ?? 00 }
   condition:
       (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule CISA_3P_10301706_01 : HiddenCobra ECCENTRICBANDWAGON backdoor keylogger reconnaissance screencapture spyware trojan
{
   meta:
       Author = "CISA Trusted Third Party"
       Incident = "10301706.r1.v1"
       Date = "2020-08-11"
       Actor = "Hidden Cobra"
       Category = "Backdoor Keylogger Reconnaissance Screen-Capture Spyware Trojan"
       Family = "ECCENTRICBANDWAGON"
       Description = "Detects strings in ECCENTRICBANDWAGON proxy tool"
       MD5_1 = "d45931632ed9e11476325189ccb6b530"
       SHA256_1 = "efd470cfa90b918e5d558e5c8c3821343af06eedfd484dfeb20c4605f9bdc30e"
       MD5_2 = "acd15f4393e96fe5eb920727dc083aed"
       SHA256_2 = "32a4de070ca005d35a88503717157b0dc3f2e8da76ffd618fca6563aec9c81f8"
       MD5_3 = "34404a3fb9804977c6ab86cb991fb130"
       SHA256_3 = "c6930e298bba86c01d0fe2c8262c46b4fce97c6c5037a193904cfc634246fbec"
       MD5_4 = "3122b0130f5135b6f76fca99609d5cbe"
       SHA256_4 = "9ea5aa00e0a738b74066c61b1d35331170a9e0a84df1cc6cef58fd46a8ec5a2e"
   strings:
       $sn1 = { FB 19 9D 57 [1-6] 9A D1 D6 D1 [1-6] 42 9E D8 FD }
       $sn2 = { 4F 03 43 83 [1-6] 48 E0 1A 2E [1-6] 3B FD FD FD }
       $sn3 = { 68 56 68 9A [1-12] 4D E1 1F 25 [1-12] 3F 38 54 0F [1-12] 73 30 62 A1 [1-12] DB 39 BD 56 }
       $sn4 = "%s\\chromeupdater_ps_%04d%02d%02d_%02d%02d%02d_%03d_%d" wide ascii nocase
       $sn5 = "c:\\windows\\temp\\TMP0389A.tmp" wide ascii nocase
   condition:
       any of them
}

rule CISA_3P_10301706_02 : HiddenCobra TWOPENCE backdoor dropper proxy spyware trojan
{
   meta:
       Author = "CISA Trusted Third Party"
       Incident = "10301706.r2.v1"
       Date = "2020-08-11"
       Actor = "Hidden Cobra"
       Category = "Backdoor Dropper Proxy Spyware Trojan"
       Family = "TWOPENCE"
       Description = "Detects strings in TWOPENCE proxy tool"
       MD5_1 = "40e698f961eb796728a57ddf81f52b9a"
       SHA256_1 = "a917c1cc198cf36c0f2f6c24652e5c2e94e28d963b128d54f00144d216b2d118"
       MD5_2 = "dfd09e91b7f86a984f8687ed6033af9d"
       SHA256_2 = "aca598e2c619424077ef8043cb4284729045d296ce95414c83ed70985c892c83"
       MD5_3 = "bda82f0d9e2cb7996d2eefdd1e5b41c4"
       SHA256_3 = "f3ca8f15ca582dd486bd78fd57c2f4d7b958163542561606bebd250c827022de"
       MD5_4 = "97aaf130cfa251e5207ea74b2558293d"
       SHA256_4 = "9a776b895e93926e2a758c09e341accb9333edc1243d216a5e53f47c6043c852"
       MD5_5 = "889e320cf66520485e1a0475107d7419"
       SHA256_5 = "8cad61422d032119219f465331308c5a61e21c9a3a431b88e1f8b25129b7e2a1"
   strings:
       $cmd1 = "ssylka"
       $cmd2 = "ustanavlivat"
       $cmd3 = "poluchit"
       $cmd4 = "pereslat"
       $cmd5 = "derzhat"
       $cmd6 = "vykhodit"
       $cmd7 = "Nachalo"
       $cmd8 = "kliyent2podklyuchit"
       $frmt1 = "Host: %s%s%s:%hu"
       $frmt2 = "%s%s%s%s%s%s%s%s%s%s"
   condition:
       (4 of ($cmd*)) and (1 of ($frmt*))
}


rule CISA_3P_10257062 : HiddenCobra FASTCASH trojan
{
   meta:
       Author = "CISA Trusted Third Party"
       Incident = "10257062"
       Date = "2020-08-11"
       Actor = "Hidden Cobra"
       Category = "Trojan"
       Family = "FASTCASH"
       Description = "Detects HiddenCobra FASTCASH samples"
       MD5_1 = "a2b1a45a242cee03fab0bedb2e460587"
       SHA256_1 = "5cb7a352535b447609849e20aec18c84d8b58e377d9c6365eafb45cdb7ef949b"
   strings:
       $sn_config_key1 = "Slsklqc^mNgq`lyznqr[q^123"
       $sn_config_key2 = "zRuaDglxjec^tDttSlsklqc^m"
       $sn_logfile1 = "C:\\intel\\_DMP_V\\spvmdl.dat"
       $sn_logfile2 = "C:\\intel\\_DMP_V\\spvmlog_%X.dat"
       $sn_logfile3 = "C:\\intel\\_DMP_V\\TMPL_%X.dat"
       $sn_logfile4 = "C:\\intel\\mvblk.dat"
       $sn_logfile5 = "C:\\intel\\_DMP_V\\spvmsuc.dat"
   condition:
       all of ($sn*)
}

rule CISA_10135536_06 : trojan rat HIDDENCOBRA BLINDINGCAN
{
   meta:
       Author = "CISA Code & Media Analysis"
       Incident = "10135536"
       Date = "2018-05-04"
       Actor = "HiddenCobra"
       Category = "Trojan RAT"
       Family = "BLINDINGCAN"
       Description = "Detects 32bit HiddenCobra BLINDINGCAN Trojan RAT"
       MD5_1 = "f9e6c35dbb62101498ec755152a8a67b"
       SHA256_1 = "1ee75106a9113b116c54e7a5954950065b809e0bb4dd0a91dc76f778508c7954"
       MD5_2 = "d742ba8cf5b24affdf77bc6869da0dc5"
       SHA256_2 = "7dce6f30e974ed97a3ed024d4c62350f9396310603e185a753b63a1f9a2d5799"
       MD5_3 = "aefcd8e98a231bccbc9b2c6d578fc8f3"
       SHA256_3 = "96721e13bae587c75618566111675dec2d61f9f5d16e173e69bb42ad7cb2dd8a"
       MD5_4 = "3a6b48871abbf2a1ce4c89b08bc0b7d8"
       SHA256_4 = "f71d67659baf0569143874d5d1c5a4d655c7d296b2e86be1b8f931c2335c0cd3"
   strings:
       $s0 = { C7 45 EC 0D 06 09 2A C7 45 F0 86 48 86 F7 C7 45 F4 0D 01 01 01 C7 45 F8 05 00 03 82 }
       $s1 = { 50 4D 53 2A 2E 74 6D 70 }
       $s2 = { 79 67 60 3C 77 F9 BA 77 7A 56 1B 68 51 26 11 96 B7 98 71 39 82 B0 81 78 }
   condition:
       any of them
}
rule CISA_10295134_01 : rat trojan HIDDENCOBRA BLINDINGCAN
{
   meta:
       Author = "CISA Code & Media Analysis"
       Incident = "10295134"
       Date = "2020-07-28"
       Last_Modified = "20200730_1030"
       Actor = "HiddenCobra"
       Category = "Trojan RAT"
       Family = "BLINDINGCAN"
       Description = "Detects 32 and 64bit HiddenCobra BlindingCan Trojan RAT"
       MD5_1 = "e7718609577c6e34221b03de7e959a8c"
       SHA256_1 = "bdfd16dc53f5c63da0b68df71c6e61bad300e59fd5748991a6b6a3650f01f9a1"
       MD5_2 = "6c2d15114ebdd910a336b6b147512a74"
       SHA256_2 = "58027c80c6502327863ddca28c31d352e5707f5903340b9e6ccc0997fcb9631d"
   strings:
       $s0 = { C7 44 24 20 0D 06 09 2A C7 44 24 24 86 48 86 F7 C7 44 24 28 0D 01 01 01 C7 44 24 2C 05 00 03 82 }
       $s1 = { C7 45 EC 0D 06 09 2A C7 45 F0 86 48 86 F7 C7 45 F4 0D 01 01 01 C7 45 F8 05 00 03 82 }
   condition:
       $s0 or $s1
}


rule CISA_3P_10135536_02 : rc4_key_2
{
   meta:
       Author = "CISA Trusted Third Party"
       Incident = "10135536"
       Date = "2018-04-19"
       Actor = "Hidden Cobra"
       Category = "n/a"
       Family = "n/a"
       Description = "n/a"
   strings:
       $s1 = { c6 ?? ?? 79 c6 ?? ?? e1 c6 ?? ?? 0a c6 ?? ?? 5d c6 ?? ?? 87 c6 ?? ?? 7d c6 ?? ?? 9f c6 ?? ?? f7 c6 ?? ?? 5d c6 ?? ?? 12 c6 ?? ?? 2e c6 ?? ?? 11 c6 ?? ?? 65 c6 ?? ?? ac c6 ?? ?? e3 c6 ?? ?? 25 }
       $s2 = { c7 ?? ?? 79 e1 0a 5d c7 ?? ?? 87 7d 9f f7 c7 ?? ?? 5d 12 2e 11 c7 ?? ?? 65 ac e3 25 }
   condition:
       (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) and any of them
}

rule CISA_3P_10135536_36 : lfsrPolynomials_handshakeBytes
{
   meta:
       Author = "CISA Trusted Third Party"
       Incident = "10135536"
       Date = "2019-12-20"
       Actor = "Hidden Cobra"
       Category = "n/a"
       Family = "n/a"
       Description = "Detects LFSR polynomials used for FakeTLS comms and the bytes exchanged after the FakeTLS handshake"
       MD5_1 = "24906e88a757cb535eb17e6c190f371f"
       SHA256_1 = "106d915db61436b1a686b86980d4af16227776fc2048f2888995326db0541438"
   strings:
       $p1 = { 01 23 45 67 }
       $p2 = { 89 AB CD EF }
       $p3 = { FE DC BA 98 }
       $p4 = { 76 54 32 10 }
       $h1 = { 44 33 22 11 }
       $h2 = { 45 33 22 11 }
   condition:
       (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) and all of them
}

rule CISA_3P_10135536_24 : success_fail_codes
{
   meta:
       Author = "CISA Trusted Third Party"
       Incident = "10135536-A"
       Date = "2017-11-14"
       Actor = "Hidden Cobra"
       Category = "n/a"
       Family = "FALLCHILL"
       Description = ""
   strings:
       $s0 = { 68 7a 34 12 00 }
       $s1 = { ba 7a 34 12 00 }
       $f0 = { 68 5c 34 12 00 }
       $f1 = { ba 5c 34 12 00 }
   condition:
       (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) and (($s0 and $f0) or ($s1 and $f1))
}

rule CryptographyFunction    
{
   meta:
       author = "CISA trusted 3rd party"
       incident = "10271944.r1.v1"
       date =    "2019-12-25"
       category = "Hidden_Cobra"
       family = "HOTCROISSANT"
   strings:
       $ALGO_crypto_1 = { 8A [1-5] 32 [1-4] 32 [1-4] 32 [1-4] 88 [1-5] 8A [1-4] 32 [1-4] 22 [1-4] 8B [1-5] 8D [3-7] 33 [1-4] 81 [3-7] C1 [1-5] C1 [1-5] 0B [1-4] 8D [1-5] 33 [1-4] 22 [1-4] C1 [1-5] 33 [1-4] 32 [1-4] 8B [1-4] 83 [1-5] C1 [1-5] 33 [1-4] C1 [1-5] C1 }
   condition:
       uint16(0) == 0x5A4D and any of them
}

rule CISA_encodedHandshakeStrings
{
   meta:
       author = "CISA trusted 3rd party"
       incident = "10271944.r3.v1"
       date =    "2019-12-25"
       category = "Hidden_Cobra"
       family = "BUFFETLINE"
   strings:
       $e1 = { dd 91 4a 1d cb 93 52 0a d0 cb 0a 4c ca d5 08 4b ca 92 4b 1d de 92 4b 1e d2 8b 5c 14 de 92 5c }
       $e2 = { 81 8c 4d 1d d1 8a 52 1d d7 8a 4c 0d 8b c8 01 4c cd 9c 5e 0b dc 97 5e 12 95 cb 4a 48 cf 9c 53 }
   condition:
       (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) and any of them
}
rule CISA_polarsslClientHello
{
   meta:
       author = "CISA trusted 3rd party"
       incident = "10271944.R3.V1"
       date =    "2019-12-25"
       category = "Hidden_Cobra"
       family = "BUFFETLINE"
   strings:
       $polarSSL = "fjiejffndxklfsdkfjsaadiepwn"
       $cliHello = "!Q@W#E$R%T^Y&U*I(O)P"
   condition:
       (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) and all of them
}

rule CISA_NK_SSL_PROXY 
{ 
   meta: 
      Author = "CISA Code & Media Analysis" 
      Incident = "10135536" 
      Date = "2018-01-09" 
      Category = "Hidden_Cobra" 
      Family = "BADCALL" 
      Description = "Detects NK SSL PROXY" 
      MD5_1 = "C6F78AD187C365D117CACBEE140F6230" 
      MD5_2 = "C01DC42F65ACAF1C917C0CC29BA63ADC" 
   strings: 
      $s0 = {8B4C24088A140880F24780C228881408403BC67CEF5E} 
      $s1 = {568B74240C33C085F67E158B4C24088A140880EA2880F247881408403BC67CEF5E} 
      $s2 = {4775401F713435747975366867766869375E2524736466} 
      $s3 = {67686667686A75797566676467667472} 
      $s4 = {6D2A5E265E676866676534776572} 
      $s5 = {3171617A5853444332337765} 
      $s6 = "ghfghjuyufgdgftr" 
      $s7 = "q45tyu6hgvhi7^%$sdf" 
      $s8 = "m*^&^ghfge4wer" 
      condition: 
         ($s0 and $s1 and $s2 and $s3 and $s4 and $s5) or ($s6 and $s7 and $s8) 
}

rule CISA_xor_add 
{ 
   meta: 
      Author = "CISA trusted 3rd party" 
      Incident = "10135536" 
      Date = "2018-04-19" 
      Category = "Hidden_Cobra" 
      Family = "n/a" 
      Description = "n/a" 
      strings: 
         $decode = { 80 ea 28 80 f2 47} 
         $encode = { 80 f2 47 80 c2 28} 
      condition: 
         uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550 and all of them 
}

rule CISA_electricfish 
{ 
   meta: 
      Author = "CISA trusted 3rd party" 
      Incident = "10135536" 
      Date = "2019-08-14" 
      Category = "Hidden_Cobra" 
      Family = "ELECTRICFISH" 
      Description = "Detects logging functionality" 
      MD5_1 = "0ba6bb2ad05d86207b5303657e3f6874" 
      SHA256_1 = "7cf5d86cc75cd8f0e22e35213a9c051b740bd4667d9879a446f06277782bffd1" 
   strings: 
      $ = "LLgcIP" 
      $ = "CCGC_LOG" 
      $ = "LLGC_LOG" 
   condition: 
      uint16(0) == 0x5a4d and uint16(uint32(0x3c)) == 0x4550 and all of them 
}

rule CISA_rsa_modulus 
{ 
   meta: 
      Author="NCCIC trusted 3rd party" 
      Incident="10135536" 
      Date = "2018/04/19" 
      category = "hidden_cobra" 
      family = "n/a" 
      description = "n/a" 
   strings: 
      $n = "bc9b75a31177587245305cd418b8df78652d1c03e9da0cfc910d6d38ee4191d40" 
   condition: (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) and any of them 
}


rule CISA_enc_PK_header 
{ 
   meta: 
      author = "NCCIC trusted 3rd party" 
      incident = "10135536" 
      date = "2018-04-12" 
      category = "hidden_cobra" 
      family = "TYPEFRAME" 
      hash0 = "3229a6cea658b1b3ca5ca9ad7b40d8d4" 
   strings: 
      $s0 = { 5f a8 80 c5 a0 87 c7 f0 9e e6 } 
      $s1 = { 95 f1 6e 9c 3f c1 2c 88 a0 5a } 
      $s2 = { ae 1d af 74 c0 f5 e1 02 50 10 } 
   condition: 
      (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) and any of them 
}


rule CISA_Enfal_Generic 
{ 
   meta: 
      author = "NCCIC trusted 3rd party" 
      incident = "10135536" 
      date = "2018-04-12" 
      category = "hidden_cobra" 
      family = "BRAMBUL,JOANAP" 
      MD5_1 = "483B95B1498B615A1481345270BFF87D" 
      MD5_2 = "4731CBAEE7ACA37B596E38690160A749" 
      MD5_3 = "CD60FD107BAACCAFA6C24C1478C345C8" 
      MD5_4 = "298775B04A166FF4B8FBD3609E716945" 
      Info = "Detects Hidden Cobra SMB Worm / RAT" 
   strings: 
      $s0 = {6D737373636172647072762E6178} 
      $s1 = {6E3472626872697138393076393D3032333D30312A2628542D30513332354A314E3B4C4B} 
      $s2 = {72656468617440676D61696C2E636F6D} 
      $s3 = {6D69737377616E673831303740676D61696C2E636F6D} 
      $s4 = {534232755365435632564474} 
      $s5 = {794159334D6559704275415756426341} 
      $s6 = {705641325941774242347A41346167664B6232614F7A4259} 
      $s7 = {AE8591916D586DE4F6FB8EE2F0BBF1F9} 
      $s8 = {F96D5DD36D6D9A87DD6D506D6D6D516D} 
      $s9 = {43616E6E6F74206372656174652072656D6F74652066696C652E} 
      $s10 = {43616E6E6F74206F70656E2072656D6F74652066696C65} 
      $s11 = {663D547D75128D85FCFEFFFF5056} 
      $s12 = {663D547D75128D85FCFEFFFF5056E88C060000E9A9000000663D557D7512} 
      $s13 = {663D567D750F8D85FCFEFFFF5056E891070000EB7C663D577D} 
      $s14 = {3141327A3342347935433678374438773945307624465F754774487349724A71} 
      $s15 = {393032356A6864686F333965686532} 
   condition: ($s0) or ($s1) or ($s2) or ($s3) or ($s4 and $s5 and $s6) or ($s7 and $s8) or ($s9 and $s10 and $s11) or ($s12 and $s13) or ($s14 and $s15) 
}



rule Lazarus_BILDINGCAN_RC4 {
    meta:
        description = "BILDINGCAN_RC4 in Lazarus"
        author = "JPCERT/CC Incident Response Group"
        hash1 = "8db272ea1100996a8a0ed0da304610964dc8ca576aa114391d1be9d4c5dab02e"

    strings:
        $customrc4 = { 75 C0 41 8B D2 41 BB 00 0C 00 00 0F 1F 80 00 00 00 00 }
            // jnz     short loc_180002E60
            // mov     edx, r10d
            // mov     r11d, 0C00h
            //nop     dword ptr [rax+00000000h]
         $id = "T1B7D95256A2001E" ascii
         $nop = { 66 66 66 66 0F 1F 84 00 00 00 00 }
         $post = "id=%s%s&%s=%s&%s=%s&%s=" ascii
         $command = "%s%sc \"%s > %s 2>&1" ascii

     condition:
         uint16(0) == 0x5a4d and 3 of them
}

rule Lazarus_BILDINGCAN_AES {
    meta:
        description = "BILDINGCAN_AES in Lazarus"
        author = "JPCERT/CC Incident Response Group"
        hash1 = "925922ef243fa2adbd138942a9ecb4616ab69580a1864429a1405c13702fe773 "

    strings:
        $AES = { 48 83 C3 04 30 43 FC 0F B6 44 1F FC 30 43 FD 0F B6 44 1F FD 30 43 FE 0F B6 44 1F FE 30 43 FF 48 FF C9 }
        $pass = "RC2zWLyG50fPIPkQ" wide
        $nop = { 66 66 66 66 0F 1F 84 00 00 00 00 }
        $confsize = { 48 8D ?? ?? ?? ?? 00 BA F0 06 00 00 E8 }
        $buffsize = { 00 00 C7 ?? ?? ??  B8 8E 03 00 }
        $rand = { 69 D2 ?? ?? 00 00 2B ?? 81 C? D2 04 00 00 }

     condition:
        uint16(0) == 0x5a4d and 3 of them
}

rule Lazarus_BILDINGCAN_module {
    meta:
        description = "BILDINGCAN_AES module in Lazarus"
        author = "JPCERT/CC Incident Response Group"

    strings:
      $cmdcheck1 = { 3D ED AB 00 00 0F ?? ?? ?? 00 00 3D EF AB 00 00 0F ?? ?? ?? 00 00 3D 17 AC 00 00 0F ?? ?? ?? 00 00 }
      $cmdcheck2 = { 3D 17 AC 00 00 0F ?? ?? ?? 00 00 3D 67 EA 00 00 0F ?? ?? ?? 00 00 }
      $recvsize = { 00 00 41 81 F8 D8 AA 02 00 }
      $nop = { 66 66 66 66 0F 1F 84 00 00 00 00 }
      $rand = { 69 D2 ?? ?? 00 00 2B ?? 81 C? D2 04 00 00 }

    condition:
      uint16(0) == 0x5a4d and 3 of them
}

rule Lazarus_Torisma_strvest {
    meta:
        description = "Torisma in Lazarus"
        author = "JPCERT/CC Incident Response Group"
        hash1 = "7762ba7ae989d47446da21cd04fd6fb92484dd07d078c7385ded459dedc726f9"

    strings:
         $post1 = "ACTION=NEXTPAGE" ascii
         $post2 = "ACTION=PREVPAGE" ascii
         $post3 = "ACTION=VIEW" ascii
         $post4 = "Your request has been accepted. ClientID" ascii
         $password = "ff7172d9c888b7a88a7d77372112d772" ascii
         $vestt = { 4F 70 46 DA E1 8D F6 41 }
         $vestsbox = { 07 56 D2 37 3A F7 0A 52 }
         $vestrns = { 41 4B 1B DD 0D 65 72 EE }

     condition:
         uint16(0) == 0x5a4d and (all of ($post*) or $password or all of ($vest*))
}

rule Lazarus_LCPDot_strings {
    meta:
        description = "LCPDot in Lazarus"
        author = "JPCERT/CC Incident Response Group"
        hash1 = "0c69fd9be0cc9fadacff2c0bacf59dab6d935b02b5b8d2c9cb049e9545bb55ce"

    strings:
         $ua = "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko" wide
         $class = "HotPlugin_class" wide
         $post = "Cookie=Enable&CookieV=%d&Cookie_Time=64" ascii

     condition:
         uint16(0) == 0x5a4d and all of them
}

rule Lazarus_Torisma_config {
    meta:
        description = "Torisma config header"
        author = "JPCERT/CC Incident Response Group"
        hash1 = "b78efeac54fa410e9e3e57e4f3d5ecc1b47fd4f7bf0d7266b3cb64cefa48f0ec"

     strings:
        $header = { 98 11 1A 45 90 78 BA F9 4E D6 8F EE }

     condition:
        all of them
}

rule Lazarus_loader_thumbsdb {
    meta:
        description = "Loader Thumbs.db malware in Lazarus"
        author = "JPCERT/CC Incident Response Group"
        hash1 = "44e4e14f8c8d299ccf5194719ab34a21ad6cc7847e49c0a7de05bf2371046f02"

     strings:
        $switchcase = { E8 ?? ?? ?? ?? 83 F8 64 74 ?? 3D C8 00 00 00 74 ?? 3D 2C 01 00 00 75 ?? E8 ?? ?? ?? ?? B9 D0 07 00 00 E8 }

     condition:
        all of them
}

rule Lazarus_Comebacker_strings {
    meta:
        description = "Comebacker malware in Lazarus"
        author = "JPCERT/CC Incident Response Group"
        hash1 = "1ff4421a99793acda5dd7412cb9a62301b14ed0a455edbb776f56471bef08f8f"

     strings:
        $postdata1 = "%s=%s&%s=%s&%s=%s&%s=%d&%s=%d&%s=%s" ascii
        $postdata2 = "Content-Type: application/x-www-form-urlencoded" wide
        $postdata3 = "Connection: Keep-Alive" wide
        $key  = "5618198335124815612315615648487" ascii
        $str1 = "Hash error!" ascii wide
        $str2 = "Dll Data Error|" ascii wide
        $str3 = "GetProcAddress Error|" ascii wide
        $str4 = "Sleeping|" ascii wide
        $str5 = "%s|%d|%d|" ascii wide

     condition:
        all of ($postdata*) or $key or all of ($str*)
}

rule Lazarus_VSingle_strings {
     meta:
        description = "VSingle malware in Lazarus"
        author = "JPCERT/CC Incident Response Group"
        hash1 = "b114b1a6aecfe6746b674f1fdd38a45d9a6bb1b4eb0b0ca2fdb270343f7c7332"
        hash2 = "63fa8ce7bf7c8324ed16c297092e1b1c5c0a0f8ab7f583ab16aa86a7992193e6"

     strings:
        $encstr1 = "Valefor was uninstalled successfully." ascii wide
        $encstr2 = "Executable Download Parameter Error" ascii wide
        $encstr3 = "Plugin Execute Result" ascii wide
        $pdb = "G:\\Valefor\\Valefor_Single\\Release\\VSingle.pdb" ascii
        $str1 = "sonatelr" ascii
        $str2 = ".\\mascotnot" ascii
        $str3 = "%s_main" ascii
        $str4 = "MigMut" ascii
        $str5 = "lkjwelwer" ascii
        $str6 = "CreateNamedPipeA finished with Error-%d" ascii
        $str7 = ".\\pcinpae" ascii
        $str8 = { C6 45 80 4C C6 45 81 00 C6 45 82 00 C6 45 83 00 C6 45 84 01 C6 45 85 14 C6 45 86 02 C6 45 87 00 }
        $xorkey1 = "o2pq0qy4ymcrbe4s" ascii wide
        $xorkey2 = "qwrhcd4pywuyv2mw" ascii wide
        $xorkey3 = "3olu2yi3ynwlnvlu" ascii wide
        $xorkey4 = "uk0wia0uy3fl3uxd" ascii wide

     condition:
        all of ($encstr*) or $pdb or 1 of ($xorkey*) or 3 of ($str*)
}

rule Lazarus_ValeforBeta_strings {
    meta:
        description = "ValeforBeta malware in Lazarus"
        author = "JPCERT/CC Incident Response Group"
        hash1 = "5f3353063153a29c8c3075ffb1424b861444a091d9007e6f3b448ceae5a3f02e"

     strings:
        $str0 = "cmd interval: %d->%d" ascii wide
        $str1 = "script interval: %d->%d" ascii wide
        $str2 = "Command not exist. Try again." ascii wide
        $str3 = "successfully uploaded from %s to %s" ascii wide
        $str4 = "success download from %s to %s" ascii wide
        $str5 = "failed with error code: %d" ascii wide

     condition:
        3 of ($str*)
}

//import "pe"

//rule Lzarus_2toy_sig {
//   meta:
//      description = "Lazarus using signature 2 TOY GUYS LLC"
//      date = "2021-02-03"
//      author = "JPCERT/CC Incident Response Group"
//      hash1 = "613f1cc0411485f14f53c164372b6d83c81462eb497daf6a837931c1d341e2da"
//      hash2 = "658e63624b73fc91c497c2f879776aa05ef000cb3f38a340b311bd4a5e1ebe5d"

//   condition:
//      uint16(0) == 0x5a4d and
//      for any i in (0 .. pe.number_of_signatures) : (
//         pe.signatures[i].issuer contains "2 TOY GUYS LLC" and
//         pe.signatures[i].serial == "81:86:31:11:0B:5D:14:33:1D:AC:7E:6A:D9:98:B9:02"
//      )
//}

rule Lazarus_packer_code {
    meta:
        description = "Lazarus using packer"
        author = "JPCERT/CC Incident Response Group"
        hash1 = "b114b1a6aecfe6746b674f1fdd38a45d9a6bb1b4eb0b0ca2fdb270343f7c7332"
        hash2 = "5f3353063153a29c8c3075ffb1424b861444a091d9007e6f3b448ceae5a3f02e"

     strings:
        $code = { 55 8B EC A1 ?? ?? ?? 00 83 C0 01 A3 ?? ?? ?? 00 83 3D ?? ?? ?? 00 ( 01 | 02 | 03 | 04 | 05 ) 76 16 8B 0D ?? ?? ?? 00 83 E9 01 89 0D ?? ?? ?? 00 B8 ?? ?? ?? ?? EB  }
     condition:
        all of them
}

rule Lazarus_Kaos_golang {
    meta:
        description = "Kaos malware in Lazarus"
        author = "JPCERT/CC Incident Response Group"
        hash1 = "6db57bbc2d07343dd6ceba0f53c73756af78f09fe1cb5ce8e8008e5e7242eae1"
        hash2 = "2d6a590b86e7e1e9fa055ec5648cd92e2d5e5b3210045d4c1658fe92ecf1944c"

     strings:
        $gofunc1 = "processMarketPrice" ascii wide
        $gofunc2 = "handleMarketPrice" ascii wide
        $gofunc3 = "EierKochen" ascii wide
        $gofunc4 = "kandidatKaufhaus" ascii wide
        $gofunc5 = "getInitEggPrice" ascii wide
        $gofunc6 = "HttpPostWithCookie" ascii wide

     condition:
        4 of ($gofunc*)
}

rule Lazarus_VSingle_elf {
    meta:
        description = "ELF_VSingle malware in Lazarus"
        author = "JPCERT/CC Incident Response Group"
        hash1 = "f789e1895ce24da8d7b7acef8d0302ae9f90dab0c55c22b03e452aeba55e1d21"

     strings:
        $code1 = { C6 85 ?? ?? FF FF 26 C6 85 ?? ?? FF FF 75 C6 85 ?? ?? FF FF 69 C6 85 ?? ?? FF FF 73 } // &uis
        $code2 = { C6 85 ?? ?? FF FF 75 C6 85 ?? ?? FF FF 66 C6 85 ?? ?? FF FF 77 } // ufw
        $code3 = { C6 85 ?? ?? FF FF 25 C6 85 ?? ?? FF FF 73 C6 85 ?? ?? FF FF 7C C6 85 ?? ?? FF FF 25 C6 85 ?? ?? FF FF 78 } // %s|%x
        $code4 = { C6 85 ?? ?? FF FF 4D C6 85 ?? ?? FF FF 6F C6 85 ?? ?? FF FF 7A C6 85 ?? ?? FF FF 69 C6 85 ?? ?? FF FF 6C C6 85 ?? ?? FF FF 6C C6 85 ?? ?? FF FF 61 C6 85 ?? ?? FF FF 2F } // Mozilla
        $code5 = { C6 84 ?? ?? ?? 00 00 25 C6 84 ?? ?? ?? 00 00 73 C6 84 ?? ?? ?? 00 00 25 C6 84 ?? ?? ?? 00 00 31 C6 84 ?? ?? ?? 00 00 75 C6 84 ?? ?? ?? 00 00 25 C6 84 ?? ?? ?? 00 00 31 C6 84 ?? ?? ?? 00 00 75 } // %s%1u%1u
     condition:
        3 of ($code*)
}

rule Lazarus_packer_upxmems {
    meta:
        description = "ELF malware packer based UPX in Lazarus"
        author = "JPCERT/CC Incident Response Group"
        hash1 = "f789e1895ce24da8d7b7acef8d0302ae9f90dab0c55c22b03e452aeba55e1d21"

     strings:
        $code1 = { 47 2C E8 3C 01 77 [10-14] 86 C4 C1 C0 10 86 C4 }
                                       // inc edi
                                       // sub al, 0E8h
                                       // cmp al, 1
                                       // xchg al, ah
                                       // rol eax, 10h
                                       // xchg al, ah
        $code2 = { 81 FD 00 FB FF FF 83 D1 02 8D } // cmp ebp, FFFFFB00h    adc ecx, 2
        $sig = "MEMS" ascii
     condition:
        all of ($code*) and #sig >= 3 and uint32(0x98) == 0x534d454d
}

rule Lazarus_httpbot_jsessid {
    meta:
        description = "Unknown HTTP bot in Lazarus"
        author = "JPCERT/CC Incident Response Group"
        hash1 = "451ad26a41a8b8ae82ccfc850d67b12289693b227a7114121888b444d72d4727"

     strings:
        $jsessid = "jsessid=%08x%08x%08x" ascii
        $http = "%04x%04x%04x%04x" ascii
        $init = { 51 68 ?? ?? ?? 00 51 BA 04 01 00 00 B9 ?? ?? ?? 00 E8 }
        $command = { 8B ?? ?? 05 69 62 2B 9F 83 F8 1D 0F ?? ?? ?? 00 00 FF}

     condition:
        $command or ($jsessid and $http and #init >= 3)
}

rule Lazarus_tool_smbscan {
    meta:
        description = "SMB scan tool in Lazarus"
        author = "JPCERT/CC Incident Response Group"
        hash1 = "d16163526242508d6961f061aaffe3ae5321bd64d8ceb6b2788f1570757595fc"
        hash2 = "11b29200f0696041dd607d0664f1ebf5dba2e2538666db663b3077d77f883195"

     strings:
        $toolstr1 = "Scan.exe StartIP EndIP ThreadCount logfilePath [Username Password Deep]" ascii
        $toolstr2 = "%s%-30s%I64d\t%04d-%02d-%02d %02d:%02d" ascii
        $toolstr3 = "%s%-30s(DIR)\t%04d-%02d-%02d %02d:%02d" ascii
        $toolstr4 = "%s U/P not Correct! - %d" ascii
        $toolstr5 = "%s %-20S%-30s%S" ascii
        $toolstr6 = "%s - %s:(Username - %s / Password - %s" ascii

     condition:
        4 of ($toolstr*)
}

rule Lazarus_simplecurl_strings {
    meta:
        description = "Tool of simple curl in Lazarus"
        author = "JPCERT/CC Incident Response Group"
        hash1 = "05ffcbda6d2e38da325ebb91928ee65d1305bcc5a6a78e99ccbcc05801bba962"
     strings:
        $str1 = "Usage: [application name].exe url filename" ascii
        $str2 = "completely succeed!" ascii
        $str3 = "InternetOpenSession failed.." ascii
        $str4 = "HttpSendRequestA failed.." ascii
        $str5 = "HttpQueryInfoA failed.." ascii
        $str6 = "response code: %s" ascii
        $str7 = "%02d.%02d.%04d - %02d:%02d:%02d:%03d :" ascii
     condition:
        4 of ($str*)
}

rule Lazarus_Dtrack_code {
     meta:
        description = "Dtrack malware in Lazarus"
        author = "JPCERT/CC Incident Response Group"
        hash = "2bcb693698c84b7613a8bde65729a51fcb175b04f5ff672811941f75a0095ed4"
        hash = "467893f5e343563ed7c46a553953de751405828061811c7a13dbc0ced81648bb"

     strings:
        $rc4key1 = "xwqmxykgy0s4"
        $rc4key2 = "hufkcohxyjrm"
        $rc4key3 = "fm5hkbfxyhd4"
        $rc4key4 = "ihy3ggfgyohx"
        $rc4key5 = "fwpbqyhcyf2k"
        $rc4key6 = "rcmgmg3ny3pa"
        $rc4key7 = "a30gjwdcypey"
        $zippass1 = "dkwero38oerA^t@#"
        $zippass2 = "z0r0f1@123"
        $str1 = "Using Proxy"
        $str2 = "Preconfig"
        $str3 = "%02d.%02d.%04d - %02d:%02d:%02d:%03d :"
        $str4 = "%02X:%02X:%02X:%02X:%02X:%02X"
        $str5 = "%s\\%c.tmp"
        $code = { 81 ?? EB 03 00 00 89 ?? ?? ?? FF FF 83 ?? ?? ?? FF FF 14 0F 87 EA 00 00 00 }

     condition:
       uint16(0) == 0x5A4D and
       uint32(uint32(0x3c)) == 0x00004550 and
       (1 of ($rc4key*) or 1 of ($zippass*) or (3 of  ($str*) and $code))
}

rule Lazarus_keylogger_str {
     meta:
        description = "Keylogger in Lazarus"
        author = "JPCERT/CC Incident Response Group"
        hash = "e0567863b10e9b1ac805292d30626ea24b28ee12f3682a93d29120db3b77a40a"

     strings:
        $mutex = "c2hvcGxpZnRlcg"
        $path = "%APPDATA%\\\\Microsoft\\\\Camio\\\\"
        $str = "[%02d/%02d/%d %02d:%02d:%02d]"
        $table1 = "CppSQLite3Exception"
        $table2 = "CppSQLite3Query"
        $table3 = "CppSQLite3DB"
        $table4 = "CDataLog"
        $table5 = "CKeyLogger"

     condition:
       uint16(0) == 0x5A4D and
       uint32(uint32(0x3c)) == 0x00004550 and
       4 of them
}

rule Lazarus_DreamJob_doc2021 {
     meta:
        description = "Malicious doc used in Lazarus operation Dream Job"
        author = "JPCERT/CC Incident Response Group"
        hash1 = "ffec6e6d4e314f64f5d31c62024252abde7f77acdd63991cb16923ff17828885"
        hash2 = "8e1746829851d28c555c143ce62283bc011bbd2acfa60909566339118c9c5c97"
        hash3 = "294acafed42c6a4f546486636b4859c074e53d74be049df99932804be048f42c"

     strings:
        $peheadb64 = "dCBiZSBydW4gaW4gRE9TIG1vZGU"
        $command1 = "cmd /c copy /b %systemroot%\\system32\\"
        $command2 = "Select * from Win32_Process where name"
        $command3 = "cmd /c explorer.exe /root"
        $command4 = "-decode"
        $command5 = "c:\\Drivers"
        $command6 = "explorer.exe"
        $command7 = "cmd /c md"
        $command8 = "cmd /c del"

     condition:
       uint16(0) == 0xCFD0 and
       $peheadb64 and 4 of ($command*)
}

rule Lazarus_boardiddownloader_code {
     meta:
        description = "boardid downloader in Lazarus"
        author = "JPCERT/CC Incident Response Group"
        hash = "fe80e890689b0911d2cd1c29196c1dad92183c40949fe6f8c39deec8e745de7f"

     strings:
        $enchttp = { C7 ?? ?? 06 1A 1A 1E C7 ?? ?? 1D 54 41 41 }
        $xorcode = { 80 74 ?? ?? 6E 80 74 ?? ?? 6E (48 83|83) ?? 02 (48|83) }

     condition:
       uint16(0) == 0x5A4D and
       uint32(uint32(0x3c)) == 0x00004550 and
       all of them
}

rule AppleJeus_UnionCrypto_code {
     meta:
        description = "UnionCrypto malware in AppleJeus"
        author = "JPCERT/CC Incident Response Group"
        hash = "295c20d0f0a03fd8230098fade0af910b2c56e9e5700d4a3344d10c106a6ae2a"

     strings:
        $http1 = "auth_timestamp:" ascii
        $http2 = "auth_signature:" ascii
        $http3 = "&act=check" ascii
        $http4 = "Windows %d(%d)-%s" ascii
        $key = "vG2eZ1KOeGd2n5fr" ascii

     condition:
       uint16(0) == 0x5A4D and
       uint32(uint32(0x3c)) == 0x00004550 and
       (all of ($http*) or $key)
}

rule AppleJeus_UnionCrypto_loader {
     meta:
        description = "UnionCrypto loader in AppleJeus"
        author = "JPCERT/CC Incident Response Group"
        hash = "949dfcafd43d7b3d59fe3098e46661c883b1136c0836f8f9219552f13607405b"

     strings:
        $xorcode = { 33 D2 4D ?? ?? 01 8B C7 FF C7 F7 F6 42 0F B? ?? ?? 41 3? 4? FF 3B FB }
        $callcode = { 48 8? ?? E8 ?? ?? 00 00 FF D3 4C }

     condition:
       uint16(0) == 0x5A4D and
       uint32(uint32(0x3c)) == 0x00004550 and
       all of them
}

rule Operation_BookCode_WebShell
{
	meta:
		author = "KrCERT/CC Profound Analysis Team"
		date = "2020-04-01"
		description  = "Operation BookCode redhat-WebShell"
		contact = "hypen@krcert.or.kr"
		ver = "1.0"

	strings:
		$string1 = "const vgo=\"admin\"" fullword ascii
		$string2 = "const nkw=\"redhat\"" fullword ascii
		$string3 = "const mam=\"want_pre.asp\"" fullword ascii
		$string4 = "const nkw=\"redhat\"" fullword ascii
		$string5 = "const pxo=\"redhat\"" fullword ascii
		$string6 = "const ydc=\"redhat hacker\"" fullword ascii
		$string7 = "const vtn=\"redhat.html\"" fullword ascii
		$string8 = "execute yka" fullword ascii

	condition:
		( filesize < 100KB 
		and all of them )
		or hash.md5(0, filesize) == "5ff8fb17133c9a2020571d6cfedd3883"
}


rule Operation_BookCode_C2page
{
	meta:
		author = "KrCERT/CC Profound Analysis Team"
		date = "2020-04-01"
	    	description  = "Operation BookCode C2pages"
		contact = "hypen@krcert.or.kr"
		ver = "1.0"

	strings:
		$C2page1_str1 = "bookcodes:200" fullword nocase ascii
		$C2page1_str2 = "bookcodes:300" fullword nocase ascii
		$C2page1_str3 = "bookcodes:400" fullword nocase ascii
		$C2page1_str4 = "bookcodes:500" fullword nocase ascii
		$C2page1_str5 = "SetPConfigInfo" fullword nocase ascii
		$C2page1_str6 = "DownLoadC" fullword nocase ascii
		$C2page1_str7 = "DownLoadS" fullword nocase ascii

		$C2page1_logfile = "config.dat" fullword nocase ascii
		$C2page1_logfile2 = "_ICEBIRD007.dat" fullword nocase ascii

		$C2page2_str1 = "Connect" fullword nocase ascii
		$C2page2_str2 = "SetConfig" fullword nocase ascii
		$C2page2_str3 = "FileDown" fullword nocase ascii
		$C2page2_str4 = "UploadSave" fullword nocase ascii

		$C2page2_logfile = "cover_img08.gif" fullword nocase ascii
		$C2page2_logfile2 =  "button_array301.gif" fullword nocase ascii

		$C2page3_str1 = "xmSub7GMQYhfi0kp.coDOnE8W2vV/H6NZle3LKUqsyzaCIjwAg9F4PtJdrTRBX1:5" fullword nocase ascii
		$C2page3_str2 = "RedirEct param:" fullword nocase ascii

		//$vbscript_encode = "<%@language=VBScript.Encode%><%#@" fullword nocase ascii
		// 위 웹셸 및 C2페이지들은 vbscript.encode로 원본 소스가 인코딩되어 검색이 안될 수도 있습니다.
		// 일부 정상 페이지도 이 방법을 사용하기 때문에 이 룰은 옵션으로 사용하시기 바랍니다.

	condition:
		(5 of ($C2page1*)) 
		or ( all of ($C2page2_str*) and 1 of ($C2page2_logfile*) ) 
		or ( all of ($C2page3*) ) 
		// 옵션 => or ($vbscript_encode) 
}


rule Operation_BookCode_RAT_Dropper
{
	meta:
		author = "KrCERT/CC Profound Analysis Team"
		date = "2020-06-22"
		info = "Operation BookCode RAT Dropper"
		contact = "hypen@krcert.or.kr"
		ver = "1.0"

		hash1 = "9F0690AD9B19283AA57149D122B2602C"
		hash2 = "45A9BCA774C28F6156A979DDF80C9D5C"

	strings:
		$parameter = { 2D 00 67 00 00 [5-15] 2D 00 73 00 00 }

		$string1 = "ServiceDll" fullword nocase wide
		$string2 = "To Puton Config" fullword nocase wide

		$file1 = { 43 32 54 30 45 36 53 34 02 3A }
		$file2 = { C6 45 ?? 43 C6 45 ?? 32 C6 45 ?? 32 C6 45 ?? 54 C6 45 ?? 30 }

	condition:
    	uint16(0) == 0x5A4D and filesize < 3MB 
		and $parameter 
		and 1 of ($string*) 
		and 1 of ($file*)
}

rule Operation_BookCode_RAT_Injector
{
	meta:
		author = "KrCERT/CC Profound Analysis Team"
		date = "2020-06-22"
		info = "Operation BookCode RAT Injector"
		contact = "hypen@krcert.or.kr"
		ver = "1.0"

		hash1 = "D76177A76F8E6484519B5B4A9BE51FFA"
		

	strings:
		$key1 = { 31 71 61 7A 32 77 73 78 33 65 }

		$string1 = "service_dll.log" fullword nocase ascii
		$string2 = "DecFile.dll" fullword nocase ascii

		$decode_string1 = { C6 45 ?? 43 C6 45 ?? 32 C6 45 ?? 32 C6 45 ?? 54 C6 45 ?? 30 }
		$decode_string2 = { 8A ?4 0D ?? [0-3] 32 C1 34 [0-3] 88 84 0D ?? ?? FF FF 41 83 F9 ?? 7C E8 }

	condition:
    	uint16(0) == 0x5A4D and filesize < 300KB 
		and $key1 
		and 1 of ($string*) 
		and 1 of ($decode_string*)
}

rule Operation_BookCode_RAT
{
	meta:
		author = "KrCERT/CC Profound Analysis Team"
		date = "2020-06-22"
		info = "Operation BookCode RAT"
		contact = "hypen@krcert.or.kr"
		ver = "1.1"

		hash1 = "EC8CDF41C32A6D8CC5A4A468637AFE74"
		hash2 = "1E38EC5BC660A7BDB229DCA8F10D77FF"
		hash3 = "AB577FBED12D8584D701AF4268426A08"
		hash5 = "4350AA8B8305B905D29022DFBFC01C0D"

	strings:
		$string_decode_64 = { 42 0F B6 4? ?? ?? [5-7] FF C2 [2-3] 42 88 8? 05 ?? 0? 00 00 83 FA ?? }
		$query_decode_64 = { 4? 8B 0? 88 14 01 4? 8B ?? [0-2] 0F B6 ?? (08|09) 4? 0F B6 ?? ?? [0-2] 0F B6 4? (08|09) 42 0F B6 }

		$string_decode_32 = { 8A ?4 0D ?? [0-3] 32 C1 34 [0-3] 88 84 0D ?? ?? FF FF 41 83 F9 ?? 7C E8 }
		$query_decode_32 = { 8B 0? 88 14 01 8B ?? 0F B6 4? 04 0F B6 ?? ?? 0F B6 4? 05 [0-1] 0F B6 }

		$command = { ?? 46 36 85 97 [10-25] ?? 47 36 85 97 }

		$string1 = "msgid=Communication" fullword nocase ascii
		$string2 = "msgid=Saves" fullword nocase ascii
		$string3 = "msgid=Savec" fullword nocase ascii
		$string4 = "msgid=Load" fullword nocase ascii
		$string5 = "msgid=Read" fullword nocase ascii
		$string6 = "msgid=Information" fullword nocase ascii
		$string7 = "msgid=Restore" fullword nocase ascii
		$string8 = "bookcodes" fullword nocase ascii
		$string9 = "server_dll.log" fullword nocase ascii


	condition:
        ( uint16(0) == 0x5A4D and filesize < 2MB and 
        (( $string_decode_64 and $query_decode_64 ) or ( $string_decode_32 and $query_decode_32 )) ) 
        or ( uint16(0) == 0x5A4D and filesize < 400KB
		and ( $command and 4 of ($string*) ))
}



rule Operation_BookCode_Downloader
{
	meta:
		author = "KrCERT/CC Profound Analysis Team"
		date = "2020-06-22"
		info = "Operation BookCode Downloader"
		contact = "hypen@krcert.or.kr"
		ver = "1.0"

		hash1 = "768981952282A1D0BC3C585916C42D44" // x86 Downloader
		hash2 = "D0E71A2C1259A72C1DCCB58651140D01" // x64 Downloader (corrupted)

	strings:

		$parameter1 = "%s %s" fullword nocase wide
		$parameter2 = "%s" fullword nocase wide

		$encode_table1 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ/:." fullword nocase ascii
		$encode_table2 = "xmSub7GMQYhfi0kp.coDOnE8W2vV/H6NZle3LKUqsyzaCIjwAg9F4PtJdrTRBX1:5" fullword nocase ascii

		$json_format1 = "\"%c\":\"%s\"" fullword nocase ascii
		$json_format2 = "{%s,\"%s\":\"" fullword nocase ascii

		$encrypt_table = { C7 45 ?? 2C FC FF FF C7 45 ?? 48 8B 4C 24 C7 45 ?? 40 48 89 41 C7 45 ?? 18 BA 46 1E C7 45 ?? 55 45 8B 4C C7 45 ?? 24 20 E8 15 C7 45 ?? FC FF FF 48 C7 45 ?? 8B 4C 24 40 }

	condition:
    	uint16(0) == 0x5A4D and filesize < 100KB 
    	and ( all of ($parameter*) and $encrypt_table )
		and ( all of ($encode_table*) and all of ($json_format*) )
}



rule Operation_BookCode_DLLInjector
{
	meta:
		author = "KrCERT/CC Profound Analysis Team"
		date = "2020-06-22"
		info = "Operation BookCode DLLInjector"
		contact = "hypen@krcert.or.kr"
		ver = "1.0"

		hash1 = "9B8C1FD0E62A52CFF1E9B67E16AC4833" // x64

	strings:

		$string = "using PID, dllpath" fullword nocase ascii
		$string2 = "Success" fullword nocase ascii
		$string3 = "Fail" fullword nocase ascii
		$string4 = "%08X" fullword nocase ascii
		$string5 = "RtlCreateUserThread" fullword nocase ascii


	condition:
    	uint16(0) == 0x5A4D and filesize < 150KB 
    	and ( all of ($string*) )
    	and pe.imphash() == "33de87c5c62a65aef22377f6ebb911bb"
}



rule Operation_BookCode_ProxyTool
{
	meta:
		author = "KrCERT/CC Profound Analysis Team"
		date = "2020-06-22"
		info = "Operation BookCode Proxy Tool"
		contact = "hypen@krcert.or.kr"
		ver = "1.0"

		hash1 = "F3CF85BA669A2CBF20FA77978E121A8A" // x64

	strings:

		$string = "C:\\Windows\\Temp\\MpMonInst.log" fullword nocase ascii
		$string2 = "<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>" fullword nocase ascii
		$string3 = "<html><head><title>503 Service Unavailable</title></head><body><h1>Service Unavailable</h1><p>The requested service was terminated on this server.</p></body></html>" fullword nocase ascii
		
		$functions = { C7 ?? [1-4] 48 74 74 70 C7 ?? [1-4] 49 6E 69 74 C7 ?? [1-4] 69 61 6C 69 [0-1] C7 ?? [1-2] 7A 65} // "HttpInitialize"
		$functions2 = { C7 ?? [1-4] 48 74 74 70 C7 ?? [1-4] 43 72 65 61 C7 ?? [1-4] 74 65 53 65 C7 ?? [1-4] 72 76 65 72 C7 ?? [1-4] 53 65 73 73 } // "HttpCreateServerSession"
		$functions3 = { C7 ?? [1-4] 48 74 74 70 C7 ?? [1-4] 43 72 65 61 C7 ?? [1-4] 74 65 55 72 C7 ?? [1-4] 6C 47 72 6F [0-1] C7 ?? [1-2] 75 70 } // "HttpCreateUrlGroup"
		$functions4 = { C7 ?? [1-4] 48 74 74 70 C7 ?? [1-4] 41 64 64 55 C7 ?? [1-4] 72 6C 54 6F C7 ?? [1-4] 55 72 6C 47 C7 ?? [1-4] 72 6F 75 70 } // "HttpAddUrlToUrlGroup"
		$functions5 = { C7 ?? [1-4] 48 74 74 70 C7 ?? [1-4] 43 72 65 61 C7 ?? [1-4] 74 65 52 65 C7 ?? [1-4] 71 75 65 73 C7 ?? [1-4] 74 51 75 65 [0-1] C7 ?? [1-4] 75 65} // "HttpCreateRequestQueue"
		$functions6 = { C7 ?? [1-4] 48 74 74 70 C7 ?? [1-4] 53 65 74 55 C7 ?? [1-4] 72 6C 47 72 C7 ?? [1-4] 6F 75 70 50 C7 ?? [1-4] 72 6F 70 65 C7 ?? [1-4] 72 74 79 00 } // "HttpSetUrlGroupProperty"


		$verify = "index.asp?%s" fullword nocase ascii
		$verify2 = "id=0" fullword nocase ascii
		$verify3 = "register.asp" fullword nocase ascii
		$verify4 = "login.asp?userid=%s" fullword nocase ascii
		$verify5 = "welcome.asp?userid=%s" fullword nocase ascii
		$verify6 = "blogview.asp?userid=%s" fullword nocase ascii

		$decode = { 80 74 04 ?? ?? 80 74 04 ?? ?? 48 83 C0 02 48 ?? 00 01 00 00 7C EA } // xor 0xB5 or 0xD9


	condition:
    	uint16(0) == 0x5A4D and filesize < 200KB 
    	and ( 2 of ($string*) )
    	and ( all of ($functions*) )
		and ( 3 of ($verify*) )
		and $decode
		or pe.imphash() == "6fd8a27de05671a7c7369e3220d9f8a7"
}



rule Operation_BookCode_Keylogger
{
	meta:
		author = "KrCERT/CC Profound Analysis Team"
		date = "2020-06-22"
		description = "Operation BookCode Keylogger"
		contact = "hypen@krcert.or.kr"
		ver = "1.0"

		hash1 = "b105912fbd3f02063af4a7875a0efd13"
		hash2 = "e1fddb1caf4793ca477f83410868d6da"

	strings:
		$str_encode = { 0F B6 04 32 48 FF C2 34 68 04 18 88 44 32 FF 48 3B D3 7C EC }

		$string1 = "[%d.%02d.%02d %02d:%02d:%02d]" fullword ascii
		$string2 = "msvcrt000.xml" fullword ascii
		$string3 = "nsvcrl001.xml" fullword ascii
		$string4 = "DomainName:%s UserName:%s SessionID:%d" fullword ascii

	condition:
		( uint16(0) == 0x5A4D and filesize < 100KB
		and ($str_encode)
		and 2 of ($string*) )
		or pe.imphash() == "9d59262ce45a7146ed25b0327b4f17fd"
}



rule Operation_BookCode_C2page_ASP_C2Pages
{
	meta:
		author = "KrCERT/CC Profound Analysis Team"
		date = "2020-06-22"
	    description  = "Operation BookCode C2pages"
		contact = "hypen@krcert.or.kr"
		ver = "1.1"

	strings:
		$C2page1_str1 = "bookcodes:200" fullword nocase ascii
		$C2page1_str2 = "bookcodes:300" fullword nocase ascii
		$C2page1_str3 = "bookcodes:400" fullword nocase ascii
		$C2page1_str4 = "bookcodes:500" fullword nocase ascii
		$C2page1_str5 = "SetPConfigInfo" fullword nocase ascii
		$C2page1_str6 = "DownLoadC" fullword nocase ascii
		$C2page1_str7 = "DownLoadS" fullword nocase ascii

		$C2page1_logfile = "config.dat" fullword nocase ascii
		$C2page1_logfile2 = "_ICEBIRD007.dat" fullword nocase ascii

		$C2page2_str1 = "Connect" fullword nocase ascii
		$C2page2_str2 = "SetConfig" fullword nocase ascii
		$C2page2_str3 = "FileDown" fullword nocase ascii
		$C2page2_str4 = "UploadSave" fullword nocase ascii

		$C2page2_logfile = "cover_img08.gif" fullword nocase ascii
		$C2page2_logfile2 =  "button_array301.gif" fullword nocase ascii

		$C2page3_str1 = "xmSub7GMQYhfi0kp.coDOnE8W2vV/H6NZle3LKUqsyzaCIjwAg9F4PtJdrTRBX1:5" fullword nocase ascii
		$C2page3_str2 = "RedirEct param:" fullword nocase ascii

		$C2page4_str1 = "<!DOCTYPE HTML PUBLIC Authentication En>;" fullword nocase ascii
		$C2page4_str2 = "Pause(int(rnd() * 1000))"
		$C2page4_str3 = "MidRequest"
		$C2page4_str4 = "ProxyCheck"
		$C2page4_str5 = "ClientHello"
		$C2page4_str6 = "ProxyLog"
		$C2page4_str7 = "Alive"

		$C2page4_logfile = "/button3.gif" fullword nocase ascii
		$C2page4_logfile2 = "/button509.gif" fullword nocase ascii

		$Midpage_str1 = "qnaboard" fullword nocase ascii
		$Midpage_str2 = "serverconnect" fullword nocase ascii
		$Midpage_str3 = "freeboard" fullword nocase ascii
		$Midpage_str4 = "relayconnect" fullword nocase ascii
		$Midpage_str5 = "bookcodes:200" fullword nocase ascii
		$Midpage_str6 = "bookcodes:400" fullword nocase ascii
		$Midpage_str7 = "bookcodes:600" fullword nocase ascii
		$Midpage_str8 = "&\"[](<\"&" nocase ascii

		$Midpage_logfile = "~XMLSTATUS1FF30.tmp" fullword nocase ascii
		$Midpage_logfile2 = "~XMLSTATUS1FF32.tmp" fullword nocase ascii

		//$vbscript_encode = "<%@language=VBScript.Encode%><%#@" fullword nocase ascii
		// 위 웹셸 및 C2페이지들은 vbscript.encode로 원본 소스가 인코딩되어 검색이 안될 수도 있습니다.
		// 일부 정상 페이지도 이 방법을 사용하기 때문에 이 룰은 옵션으로 사용하시기 바랍니다.

	condition:
		(5 of ($C2page1*)) 
		or ( all of ($C2page2_str*) and 1 of ($C2page2_logfile*) ) 
		or ( all of ($C2page3_str*) ) 
		or ( all of ($C2page4_str*) and 1 of ($C2page4_logfile*) )
		or ( 5 of ($Midpage*) )
		//or ($vbscript_encode) // <- 옵션 
}



rule Operation_BookCode_Venus_WebShell : Venus_ASP_WebShell
{
	meta:
		author = "KrCERT/CC Profound Analysis Team"
		date = "2020-06-22"
		description  = "Operation BookCode Venus-WebShell"
		contact = "hypen@krcert.or.kr"
		ver = "1.0"

	strings:
		$string1 = "Const enc_key = \"20dcc50\"" fullword nocase ascii
		$string2 = "strPwd = enc_key" fullword nocase ascii
		$string3 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" fullword nocase ascii
		$string4 = "<h2>Input Password.</h2>" fullword nocase ascii
		$string5 = "C:\\Windows\\system32\\cmd.exe" fullword nocase ascii
		$string6 = "j = (j + s[i] + key.charCodeAt(i % key.length)) % 256" fullword nocase ascii
		$string7 = "var enc_key = '\" & enc_key & \"';" fullword nocase ascii

	condition:
		( filesize < 75KB 
		and 4 of them )
		or hash.md5(0, filesize) == "29fce0c374517cddd66be394c6805ecd"
}

rule Operation_BookCode_Hunters_WebShell : Code_Hunters_ASP_WebShell
{
	meta:
		author = "KrCERT/CC Profound Analysis Team"
		date = "2020-06-22"
		description  = "Operation BookCode Code-Hunters-WebShell"
		contact = "hypen@krcert.or.kr"
		ver = "1.0"

	strings:
		$string1 = "<title>Code Hunters Shell</title>"
		$string2 = "Select Case islem" nocase ascii

		$string3 = "?islem=CreateFile" nocase ascii
		$string4 = "?islem=FolderMove" nocase ascii
		$string5 = "?islem=FolderCopy" nocase ascii
		$string6 = "?islem=FolderDelete" nocase ascii
		$string7 = "?islem=FileRename" nocase ascii
		$string8 = "?islem=indir" nocase ascii

		$string9 = "Case \"git\"" nocase ascii
		$string10 = "Case \"Drivers\"" nocase ascii
		$string11 = "Case \"Read\"" nocase ascii
		$string12 = "Case \"FileRename\"" nocase ascii
		$string13 = "Case \"Edit\"" nocase ascii
		$string14 = "Case \"FolderRename\"" nocase ascii
		$string15 = "Case \"FolderMove\"" nocase ascii
		$string16 = "Case \"FolderCopy\"" nocase ascii
		$string17 = "Case \"FileCopy\"" nocase ascii
		$string18 = "Case \"FileMove\"" nocase ascii
		$string19 = "Case \"FolderDelete\"" nocase ascii

		$string20 = "BinaryStream.SaveToFile Path&\"\\\"&Right(Url,(len(Url)-instrrev(Url,\"/\"))), 2" nocase ascii


	condition:
		( filesize < 30KB 
		and 10 of them )
		or hash.md5(0, filesize) == "e84ad76f04db2bccbab374b60c0ab349"
}

rule Operation_BookCode_WSO_WebShell : WSO_PHP_WebShell
{
	meta:
		author = "KrCERT/CC Profound Analysis Team"
		date = "2020-06-22"
		description  = "Operation BookCode WSO-WebShell"
		contact = "hypen@krcert.or.kr"
		ver = "1.0"

	strings:
		$string1 = "<?php"
		$string2 = "eval(\"?>\"" fullword nocase ascii
		$string3 = "gzuncompress(base64_decode(\"eJzlvWtXG8cSKPr" nocase ascii

	condition:
		( filesize < 30KB 
		and all of them )
		or hash.md5(0, filesize) == "3cd5fc0bac4405e39bd89f4bae478d2a"
}


rule Operation_BookCode_RedHat_WebShell: Redhat_ASP_WebShell
{
	meta:
		author = "KrCERT/CC Profound Analysis Team"
		date = "2020-06-22"
		description  = "Operation BookCode RedHat-WebShell"
		contact = "hypen@krcert.or.kr"
		ver = "1.0"

	strings:
		$string1 = "const vgo=\"admin\"" fullword ascii
		$string2 = "const nkw=\"redhat\"" fullword ascii
		$string3 = "const mam=\"want_pre.asp\"" fullword ascii
		$string4 = "const nkw=\"redhat\"" fullword ascii
		$string5 = "const pxo=\"redhat\"" fullword ascii
		$string6 = "const ydc=\"redhat hacker\"" fullword ascii
		$string7 = "const vtn=\"redhat.html\"" fullword ascii
		$string8 = "execute yka" fullword ascii

    condition:
		( filesize < 100KB 
		and all of them )
		or hash.md5(0, filesize) == "5ff8fb17133c9a2020571d6cfedd3883"
}
