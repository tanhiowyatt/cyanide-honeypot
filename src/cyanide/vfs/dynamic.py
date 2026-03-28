import datetime
import secrets
import time
from typing import Any, Dict, Optional


# Function 281: Provides dynamic content for virtual files.
def uptime_provider(context: Any, args: Optional[Dict[str, Any]] = None) -> str:
    """Returns a realistic uptime string."""
    start_time = time.time() - secrets.SystemRandom().randint(3600, 86400 * 30)
    uptime_sec = time.time() - start_time
    idle_sec = uptime_sec * 0.9
    return f"{uptime_sec:.2f} {idle_sec:.2f}\n"


# Function 282: Provides dynamic content for virtual files.
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


# Global cache to track the last seen IP for each attacker (by their source IP)
# This allows 'Last login' in the MOTD to reflect their own IP on subsequent logins.
LAST_LOGINS: Dict[str, str] = {}


# Function 282.1: Provides dynamic content for virtual files.
def motd_provider(context: Any, args: Optional[Dict[str, Any]] = None) -> str:
    """Returns a realistic OS-specific MOTD banner."""
    args = args or {}
    src_ip = str(args.get("src_ip", ""))

    os_name = getattr(context, "os_name", "Ubuntu 22.04.1 LTS")
    kernel = getattr(context, "kernel_version", "5.15.0-41-generic")
    arch = getattr(context, "arch", "x86_64")

    banner_parts = ["\r\n"]

    if "Ubuntu" in os_name:
        banner_parts.append(f"Welcome to {os_name} (GNU/Linux {kernel} {arch})\r\n\r\n")
        banner_parts.append(" * Documentation:  https://help.ubuntu.com\r\n")
        banner_parts.append(" * Management:     https://landscape.canonical.com\r\n")
        banner_parts.append(" * Support:        https://ubuntu.com/advantage\r\n")
    elif "CentOS" in os_name:
        banner_parts.append(f"Welcome to {os_name} (GNU/Linux {kernel} {arch})\r\n\r\n")
        banner_parts.append(" * Documentation:  https://docs.centos.org\r\n")
        banner_parts.append(" * Community:      https://www.centos.org/community/\r\n")
    elif "Debian" in os_name:
        banner_parts.append(f"Welcome to {os_name} (GNU/Linux {kernel} {arch})\r\n\r\n")
        banner_parts.append(" * Documentation:  https://www.debian.org/doc/\r\n")
        banner_parts.append(" * Support:        https://www.debian.org/support\r\n")
    else:
        banner_parts.append(f"Welcome to {os_name} ({kernel} {arch})\r\n")

    # Add randomized 'Last login' info
    now = datetime.datetime.now()
    last_login_date = now - datetime.timedelta(days=secrets.SystemRandom().randint(1, 10))
    date_str = last_login_date.strftime("%a %b %d %H:%M:%S %Y")

    # Check if we've seen this attacker before
    last_ip = LAST_LOGINS.get(src_ip)
    if not last_ip:
        # If first time, use a plausible internal management IP
        mgmt_ips = ["192.168.1.10", "192.168.1.25", "10.0.0.5", "172.168.5.20"]
        last_ip = secrets.SystemRandom().choice(mgmt_ips)

    # Update for NEXT time: store the current IP as the 'last seen' for this source
    if src_ip:
        LAST_LOGINS[src_ip] = src_ip

    banner_parts.append(f"\r\nLast login: {date_str} from {last_ip}\r\n")

    return "".join(banner_parts)


PROVIDERS = {
    "uptime_provider": uptime_provider,
    "cpuinfo_provider": cpuinfo_provider,
    "motd_provider": motd_provider,
}
