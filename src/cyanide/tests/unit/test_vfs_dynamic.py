from cyanide.vfs.dynamic import (
    cpuinfo_provider,
    meminfo_provider,
    motd_provider,
    shadow_provider,
    uptime_provider,
)


class MockContext:
    def __init__(self):
        self.os_name = "Ubuntu 22.04.1 LTS"
        self.kernel_version = "5.15.0-41-generic"
        self.arch = "x86_64"


def test_uptime_provider():
    res = uptime_provider(None)
    assert len(res.split()) == 2
    assert float(res.split()[0]) > 0


def test_cpuinfo_provider():
    res = cpuinfo_provider(None)
    assert "vendor_id" in res
    assert "model name" in res


def test_motd_provider():
    ctx = MockContext()
    # Test Ubuntu - first login (should show random management IP)
    res = motd_provider(ctx, {"src_ip": "1.2.3.4"})
    assert "Welcome to Ubuntu" in res

    # Second login (should show previous IP)
    res = motd_provider(ctx, {"src_ip": "1.2.3.4"})
    assert "1.2.3.4" in res

    # Test CentOS
    ctx.os_name = "CentOS Stream 9"
    res = motd_provider(ctx, {"src_ip": "1.2.3.4"})
    assert "Welcome to CentOS" in res

    # Test Debian
    ctx.os_name = "Debian GNU/Linux 11"
    res = motd_provider(ctx, {"src_ip": "5.6.7.8"})
    assert "Welcome to Debian" in res

    # Verify IP recorded for next time
    res = motd_provider(ctx, {"src_ip": "5.6.7.8"})
    assert "5.6.7.8" in res

    # Test Other
    ctx.os_name = "Arch Linux"
    res = motd_provider(ctx)
    assert "Welcome to Arch Linux" in res


def test_meminfo_provider():
    res = meminfo_provider(None)
    assert "MemTotal" in res
    assert "MemFree" in res


def test_shadow_provider():
    res = shadow_provider(None)
    assert "root:" in res
    assert "admin:" in res
