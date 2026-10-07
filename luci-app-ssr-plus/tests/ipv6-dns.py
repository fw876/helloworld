#!/usr/bin/env python3
"""Exercise DNS generation with BusyBox awk, both backends and all run modes."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

source = Path(__file__).resolve().parents[1] / 'root/usr/share/shadowsocksr/gfw2ipset.sh'
with tempfile.TemporaryDirectory(prefix='ssr6-dns-') as tmp:
    root = Path(tmp)
    config = root / 'config'
    output = root / 'output'
    init = root / 'etc/init.d'
    for directory in (config, output, init, root / 'bin'):
        directory.mkdir(parents=True)
    for name in ('gfw_base.conf', 'gfw_list.conf'):
        (config / name).write_text(''.join(
            f'server=/{domain}/127.0.0.1#5335\nipset=/{domain}/gfwlist\n'
            for domain in ('proxy.example', 'white.example', 'black.example', 'deny.example')))
    for name, domain in [('white', 'white'), ('black', 'black'), ('deny', 'deny')]:
        (config / f'{name}.list').write_text(f'# comment\n\n{domain}.example\n')
    (init / 'shadowsocksr').write_text('''
check_run_environment() { USE_TABLES="$BACKEND"; }
echolog() { :; }
normalize_run_mode() { echo "$MODE"; }
ipv6_enabled() { [ "$V6" = 1 ] && [ "$USE_TABLES" = nftables ]; }
uci_get_by_type() { echo 0; }
TMP_DNSMASQ_PATH="$TEST_OUTPUT"
dns_port=5335
''')
    script = root / 'generate.sh'
    script.write_text(source.read_text().replace('/etc/ssrplus/', str(config) + '/'))
    busybox = shutil.which('busybox')
    if not busybox:
        raise SystemExit('BusyBox is required to test the OpenWrt awk dialect')
    (root / 'bin/awk').symlink_to(busybox)
    count = 0
    for backend in ('nftables', 'iptables'):
        for mode in ('gfw', 'router', 'all'):
            for ipv6 in ('0', '1'):
                env = dict(os.environ, BACKEND=backend, MODE=mode, V6=ipv6,
                           IPKG_INSTROOT=tmp, TEST_OUTPUT=str(output),
                           PATH=str(root / 'bin') + ':' + os.environ['PATH'])
                subprocess.run([busybox, 'sh', str(script)], env=env, check=True)
                gfw = (output / 'gfw_list.conf').read_text()
                white = (output / 'whitelist_forward.conf').read_text()
                black = (output / 'blacklist_forward.conf').read_text()
                assert 'proxy.example' in gfw
                for domain in ('white.example', 'black.example', 'deny.example'):
                    assert domain not in gfw, (backend, mode, ipv6, domain)
                assert 'server=' not in white
                assert 'server=/black.example/127.0.0.1#5335' in black
                if backend == 'nftables':
                    assert '4#inet#ss_spec#whitelist_domain' in white
                    assert ('6#inet#ss_spec#whitelist_domain6' in white) == (ipv6 == '1')
                    assert ('6#inet#ss_spec#blacklist6' in black) == (ipv6 == '1')
                    if mode == 'gfw':
                        assert '4#inet#ss_spec#gfwlist' in gfw
                        assert ('6#inet#ss_spec#gfwlist6' in gfw) == (ipv6 == '1')
                    else:
                        assert 'nftset=' not in gfw and 'ipset=' not in gfw
                else:
                    assert 'nftset=' not in gfw + white + black
                    assert ('ipset=/proxy.example/gfwlist' in gfw) == (mode == 'gfw')
                count += 1
    print(f'PASS: {count} DNS generation combinations, domain overrides and AAAA sets')
