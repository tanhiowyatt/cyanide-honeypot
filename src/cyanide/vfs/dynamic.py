import random
import time
from typing import Any, Dict, Optional


def uptime_provider(context: Any, args: Optional[Dict[str, Any]] = None) -> str:
    """Returns a realistic uptime string."""
    # Start time is some random point in the past
    start_time = time.time() - random.randint(3600, 86400 * 30)
    uptime_sec = time.time() - start_time
    idle_sec = uptime_sec * 0.9
    return f"{uptime_sec:.2f} {idle_sec:.2f}\n"


def cpuinfo_provider(context: Any, args: Optional[Dict[str, Any]] = None) -> str:
    """Returns a fake cpuinfo string."""
    return """processor\t: 0
vendor_id\t: GenuineIntel
cpu family\t: 6
model\t\t: 158
model name\t: Intel(R) Core(TM) i7-8700K CPU @ 3.70GHz
stepping\t: 10
microcode\t: 0xca
cpu MHz\t\t: 3696.000
cache size\t: 12288 KB
flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush dts acpi mmx fxsr sse sse2 ss ht tm pbe syscall nx pdpe1gb rdtscp lm constant_tsc art arch_perfmon pebs bts rep_good nopl xtopology nonstop_tsc cpuid aperfmperf pni pclmulqdq dtes64 monitor ds_cpl vmx smx est tm2 ssse3 sdbg fma cx16 xtpr pdcm pcid sse4_1 sse4_2 x2apic movbe popcnt tsc_deadline_timer aes xsave avx f16c rdrand lahf_lm abm 3dnowprefetch cpuid_fault epb invpcid_single pti ssbd ibrs ibpb stibp tpr_shadow vnmi flexpriority ept vpid ept_ad fsgsbase tsc_adjust bmi1 hle avx2 smep bmi2 erms invpcid rtm mpx rdseed adx smap clflushopt intel_pt xsaveopt xsavec xgetbv1 xsaves dtherm ida arat pln pts hwp hwp_notify hwp_act_window hwp_epp md_clear flush_l1d
bugs\t\t: cpu_meltdown spectre_v1 spectre_v2 spec_store_bypass l1tf mds swapgs taa itlb_multihit srbds
bogomips\t: 7392.00
clflush size\t: 64
cache_alignment\t: 64
address sizes\t: 39 bits physical, 48 bits virtual
power management:
"""


# Registry of available providers
PROVIDERS = {
    "uptime_provider": uptime_provider,
    "cpuinfo_provider": cpuinfo_provider,
}
