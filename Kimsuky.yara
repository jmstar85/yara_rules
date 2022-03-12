import "pe"
import "hash"
import "math"

rule AppleSeed
{
	meta:
		author = "KrCERT/CC Profound Analysis Team"
        		date = "2020-12-04"
        		info = "Operation MUZABI"
        		ver = "1.0"
	strings:
		$appleseed_str1 = {0F 8? ?? (00|01) 00 00 [0-1] 83 F? 20 0F 8? ?? (01|00) 00 00 }
		$appleseed_str2 = {88 45 [0-15] 0F B6 44 ?? 01}
		$appleseed_str3 = {83 F? 10 [0-5] 83 E? 10}
		$appleseed_key1 = {89 04 ?9 [0-6] FF 34 ?? E8 [10-16] 89 0C 98 8B ?? 0C [0-3] FF 34 98 }
		$appleseed_key2 = {83 F? 10 [0-10] 32 4C 05 ?? ?? 88 4C ?? 0F}
		$appleseed_key3 = {89 04 ?9 49 83 ?? 04 48 ?? ?? 10 8B 0C A8 E8 [0-10] 48 8B ?? ?8 }
		$seed_str1 = {44 0F B6 44 3D C0 45 32 C7 44 32 45 D4}
		$seed_str2 = {0F B6 44 3? ?? [0-25] 83 C4 0C}
		$seed_str3 = {32 45 C? ?? ?? ?? 32 45 E?}
	condition:
		(uint16(0) == 0x5A4D) and (filesize < 400KB) and (2 of ($appleseed_str*)) and (1 of ($seed_str*)) and (1 of ($appleseed_key*))
}
