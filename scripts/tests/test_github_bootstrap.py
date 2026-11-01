#!/usr/bin/env python3
"""Source-exact bootstrap functions, real filesystem/TTY/curl and disposable HTTPS.

The credential fixture is synthetic, never a PAT. No Hub or live release requests.
"""
from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import pty
import select
import shlex
import shutil
import socketserver
import ssl
import subprocess
import tempfile
import termios
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
SH = ROOT / 'crates/agent/assets/install-hostlink-agent.sh'
PS = ROOT / 'crates/agent/assets/Install-HostLink-Agent.ps1'
API = 'https://api.github.com/repos/KDmasterLOL/hostlink/releases/assets/'
CDN = 'https://release-assets.githubusercontent.com/fixture'
FIXTURE = b'synthetic_fixture_only'


def helpers(source):
    return source.split('# BEGIN GITHUB BOOTSTRAP HELPERS\n', 1)[1].split('# END GITHUB BOOTSTRAP HELPERS', 1)[0]


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        # Credentials deliberately reject writable ancestors such as /tmp.
        self.temp = tempfile.TemporaryDirectory(prefix='.github-bootstrap-test-', dir=ROOT)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.home = self.root / 'home'
        self.home.mkdir(mode=0o700)
        # HOME MCP's id-mapped mount reports / and /home as uid 65534,
        # though these are the container's system-owned anchors. Emulate
        # normal Linux uid 0 for exactly those two stat checks; every
        # user-controlled path still uses real stat ownership/mode data.
        self.bin = self.root / 'test-bin'
        self.bin.mkdir(mode=0o700)
        wrapper = self.bin / 'stat'
        wrapper.write_text("#!/bin/sh\nif [ \"$1\" = -c ] && [ \"$2\" = %u ] && { [ \"$3\" = / ] || [ \"$3\" = /home ]; }; then printf '0\\n'; else exec /usr/bin/stat \"$@\"; fi\n")
        wrapper.chmod(0o700)
        self.env = {**os.environ, 'HOME': str(self.home), 'XDG_CONFIG_HOME': '', 'PATH': str(self.bin) + ':' + os.environ.get('PATH', '/usr/bin:/bin')}
        self.credential = self.home / '.config/hostlink/credentials/github-token'

    def run_sh(self, code, **kwargs):
        return subprocess.run(['/bin/sh', '-eu', '-c', helpers(SH.read_text()) + '\n' + code],
                              env=self.env, capture_output=True, timeout=15, **kwargs)

    def require_safe_ancestry(self):
        result = self.run_sh('hl_safe_chain "$HOME"')
        if result.returncode != 0:
            self.skipTest('sandbox UID mapping prevents trusted root ancestry: ' + result.stderr.decode().strip())

    def put_credential(self):
        self.require_safe_ancestry()
        self.credential.parent.mkdir(mode=0o700, parents=True)
        self.credential.parent.parent.chmod(0o700)
        self.credential.write_bytes(FIXTURE)
        self.credential.chmod(0o600)

    def test_asset_urls_are_fixed_api_and_positive_numeric_id(self):
        for suffix in ('1', '293847561029384756102938475610'):
            self.assertEqual(self.run_sh('hl_asset_url ' + shlex.quote(API + suffix)).returncode, 0)
        for url in (API, API + '0', API + '01', API + '-1', API + '1/x', API + '1?q=2',
                    API + '1#x', API + '1%0a', API + '1\n', API.replace('https:', 'http:') + '1',
                    API.replace('api.github.com', 'api.github.com.evil') + '1',
                    API.replace('api.github.com', 'user@api.github.com') + '1',
                    API.replace('KDmasterLOL', 'another') + '1'):
            self.assertNotEqual(self.run_sh('hl_asset_url ' + shlex.quote(url)).returncode, 0)

    def test_existing_credential_is_readonly_and_never_reprompted(self):
        self.put_credential()
        before = self.credential.stat()
        result = self.run_sh('hl_provision_credential')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn(FIXTURE, result.stdout + result.stderr)
        after = self.credential.stat()
        self.assertEqual((before.st_ino, before.st_mtime_ns, before.st_mode),
                         (after.st_ino, after.st_mtime_ns, after.st_mode))
        self.assertEqual(self.credential.read_bytes(), FIXTURE)

    def test_explicit_controller_credential_provisions_without_target_prompt(self):
        self.require_safe_ancestry()
        quoted = shlex.quote(FIXTURE.decode('ascii'))
        # No PTY attached: the controller-supplied string must avoid Read-Host.
        result = self.run_sh('hl_provision_credential ' + quoted)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn(FIXTURE, result.stdout + result.stderr)
        self.assertEqual(self.credential.read_bytes(), FIXTURE)
        self.assertEqual(self.credential.stat().st_mode & 0o777, 0o600)
        for directory in (self.credential.parent, self.credential.parent.parent):
            self.assertEqual(directory.stat().st_mode & 0o777, 0o700)

        before = self.credential.stat()
        result = self.run_sh('hl_provision_credential ' + quoted)
        self.assertEqual(result.returncode, 0, result.stderr)
        after = self.credential.stat()
        self.assertEqual((before.st_ino, before.st_mtime_ns), (after.st_ino, after.st_mtime_ns))

        # A different shared PAT must never silently replace an existing one.
        wrong = b'synthetic_other_fixture'
        result = self.run_sh('hl_provision_credential ' + shlex.quote(wrong.decode()))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'rotate it explicitly', result.stderr)
        self.assertNotIn(FIXTURE, result.stdout + result.stderr)
        self.assertNotIn(wrong, result.stdout + result.stderr)
        self.assertEqual(self.credential.read_bytes(), FIXTURE)

    def test_invalid_embedded_credential_fails_without_interactive_fallback(self):
        self.require_safe_ancestry()
        for value in ('', 'bad\nheader', 'bad token', 'bad"quote', 'a' * 1025):
            result = self.run_sh('hl_provision_credential ' + shlex.quote(value))
            self.assertNotEqual(result.returncode, 0)
            if value:
                self.assertNotIn(value.encode(), result.stderr)
            self.assertFalse(self.credential.exists())
        self.assertNotEqual(self.run_sh('hl_provision_credential a b').returncode, 0)

    def test_weak_symlink_hardlink_and_mutable_parent_are_refused(self):
        self.put_credential()
        for mode in (0o644, 0o660, 0o666):
            self.credential.chmod(mode)
            self.assertNotEqual(self.run_sh('hl_load_credential').returncode, 0)
        self.credential.chmod(0o600)
        link = self.root / 'linked'
        os.link(self.credential, link)
        self.assertNotEqual(self.run_sh('hl_load_credential').returncode, 0)
        link.unlink()
        self.credential.rename(link)
        self.credential.symlink_to(link)
        self.assertNotEqual(self.run_sh('hl_provision_credential').returncode, 0)
        self.credential.unlink()
        link.rename(self.credential)
        self.home.chmod(0o777)
        self.assertNotEqual(self.run_sh('hl_load_credential').returncode, 0)
        self.home.chmod(0o700)
        directory = self.credential.parent
        moved = directory.with_name('original')
        directory.rename(moved)
        directory.symlink_to(moved, target_is_directory=True)
        self.assertNotEqual(self.run_sh('hl_load_credential').returncode, 0)

    def test_absolute_xdg_and_relative_xdg_uses_home_default(self):
        self.put_credential()
        self.env['XDG_CONFIG_HOME'] = 'relative-path-is-ignored'
        self.assertEqual(self.run_sh('hl_load_credential; unset hl_github_token').returncode, 0)
        config = self.root / 'config'
        self.home.joinpath('.config').rename(config)
        self.env['XDG_CONFIG_HOME'] = str(config)
        self.assertEqual(self.run_sh('hl_load_credential; unset hl_github_token').returncode, 0)
        config.rename(self.root / 'original')
        config.symlink_to(self.root / 'original', target_is_directory=True)
        self.assertNotEqual(self.run_sh('hl_load_credential').returncode, 0)

    def test_secret_target_prompt_creates_private_file_without_echo(self):
        if os.getuid() == 0:
            self.skipTest('interactive bootstrap intentionally rejects root')
        self.require_safe_ancestry()
        master, slave = pty.openpty()
        self.addCleanup(os.close, master)
        def terminal():
            os.setsid()
            fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
        process = subprocess.Popen(['/bin/sh', '-eu', '-c', helpers(SH.read_text()) + '\nhl_provision_credential'],
                                   env=self.env, stdin=slave, stdout=slave, stderr=slave, preexec_fn=terminal)
        os.close(slave)
        self.addCleanup(lambda: process.poll() is None and process.kill())
        output = b''
        deadline = time.monotonic() + 5
        while b'Contents:Read only): ' not in output:
            self.assertLess(time.monotonic(), deadline, 'target prompt deadline')
            if select.select([master], [], [], 0.1)[0]:
                output += os.read(master, 4096)
        # The prompt is printed before echo is disabled; wait for the terminal flag.
        while termios.tcgetattr(master)[3] & termios.ECHO:
            self.assertLess(time.monotonic(), deadline, 'target terminal echo stayed enabled')
            time.sleep(0.01)
        os.write(master, FIXTURE + b'\n')
        self.assertEqual(process.wait(timeout=5), 0)
        try:
            while select.select([master], [], [], 0)[0]:
                output += os.read(master, 4096)
        except OSError:
            pass
        self.assertNotIn(FIXTURE, output)
        self.assertEqual(self.credential.read_bytes(), FIXTURE)
        self.assertEqual(self.credential.stat().st_mode & 0o777, 0o600)
        for directory in (self.credential.parent, self.credential.parent.parent):
            self.assertEqual(directory.stat().st_mode & 0o777, 0o700)

    @contextmanager
    def https_fixture(self):
        if not shutil.which('openssl') or not shutil.which('curl'):
            self.skipTest('openssl and curl are required for the real HTTPS fixture')
        records = []
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        cert, key = self.root / 'cert.pem', self.root / 'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(key), '-out', str(cert), '-days', '1', '-subj', '/CN=api.github.com',
                        '-addext', 'subjectAltName=DNS:api.github.com,DNS:release-assets.githubusercontent.com'],
                       check=True, capture_output=True)
        context.load_cert_chain(cert, key)
        class Handler(socketserver.BaseRequestHandler):
            def handle(handler):
                connection = handler.request
                connection.settimeout(3)
                connect = b''
                while not connect.endswith(b'\r\n\r\n'):
                    connect += connection.recv(1)
                if not connect.startswith(b'CONNECT '):
                    return
                connection.sendall(b'HTTP/1.1 200 Connection established\r\n\r\n')
                try:
                    with context.wrap_socket(connection, server_side=True) as stream:
                        request = b''
                        while not request.endswith(b'\r\n\r\n'):
                            request += stream.recv(1)
                        lines = request.decode('ascii').split('\r\n')
                        path = lines[0].split()[1]
                        headers = dict(line.split(': ', 1) for line in lines[1:] if ': ' in line)
                        records.append((path, headers))
                        if path.endswith('/2'):
                            response = ('HTTP/1.1 302 Found\r\nLocation: ' + CDN + '\r\nContent-Length: 0\r\n\r\n').encode()
                        elif path.endswith('/3'):
                            response = b'HTTP/1.1 302 Found\r\nLocation: http://release-assets.githubusercontent.com/no\r\nContent-Length: 0\r\n\r\n'
                        elif path.endswith('/4'):
                            response = b'HTTP/1.1 200 OK\r\nContent-Length: 9999999\r\n\r\n'
                        elif path.endswith('/5'):
                            response = b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n400\r\n' + b'x'*1024 + b'\r\n0\r\n\r\n'
                        elif path.endswith('/6'):
                            response = ('HTTP/1.1 302 Found\r\nLocation: ' + CDN + '-loop\r\nContent-Length: 0\r\n\r\n').encode()
                        elif path == '/fixture-loop':
                            response = ('HTTP/1.1 302 Found\r\nLocation: ' + CDN + '\r\nContent-Length: 0\r\n\r\n').encode()
                        elif path.endswith('/7'):
                            response = b'HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n'
                        else:
                            response = b'HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nfixture'
                        stream.sendall(response)
                except (ssl.SSLError, OSError):
                    pass
        class Server(socketserver.ThreadingTCPServer):
            daemon_threads = True
            allow_reuse_address = True
        try:
            server = Server(('127.0.0.1', 0), Handler)
        except PermissionError as error:
            self.skipTest('sandbox denied disposable loopback bind: ' + str(error))
        with server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self.env.update(HTTPS_PROXY='http://127.0.0.1:' + str(server.server_address[1]),
                            https_proxy='http://127.0.0.1:' + str(server.server_address[1]),
                            NO_PROXY='', no_proxy='', CURL_CA_BUNDLE=str(cert))
            try:
                yield records
            finally:
                server.shutdown()
                thread.join(timeout=3)

    def test_real_curl_200_302_auth_isolation_caps_cleanup_and_no_fallback(self):
        # Try loopback first so its independent sandbox blocker is reported.
        with self.https_fixture() as records:
            self.put_credential()
            for suffix in ('1', '2'):
                dest = self.root / ('asset' + suffix)
                result = self.run_sh('hl_download ' + shlex.quote(API + suffix) + ' ' + shlex.quote(str(dest)) + ' 512 5')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(dest.read_bytes(), b'fixture')
                self.assertNotIn(FIXTURE, result.stdout + result.stderr)
            self.assertEqual(len(records), 3)
            self.assertEqual(records[0][1].get('Authorization', '').encode(), b'Bearer ' + FIXTURE)
            self.assertEqual(records[1][1].get('Authorization', '').encode(), b'Bearer ' + FIXTURE)
            self.assertNotIn('Authorization', records[2][1])
            self.assertNotIn('Referer', records[2][1])
            for suffix in ('3', '4', '5', '6', '7'):
                dest = self.root / ('asset' + suffix)
                result = self.run_sh('hl_download ' + shlex.quote(API + suffix) + ' ' + shlex.quote(str(dest)) + ' 512 5')
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(dest.exists(), 'partial download must be removed')
                self.assertNotIn(FIXTURE, result.stdout + result.stderr)
            self.assertEqual(len(records), 9, 'one initial call each, at most one no-auth CDN call')

    def test_mutable_local_ancestor_is_rejected_before_any_credential_read(self):
        self.home.chmod(0o777)
        result = self.run_sh('hl_safe_chain "$HOME"')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'writable by other users', result.stderr)
        self.home.chmod(0o700)

    def test_windows_static_security_and_ps2_contract(self):
        script = PS.read_text()
        shared = helpers(script)
        for unsupported in ('Invoke-WebRequest', 'ConvertFrom-Json', '[ordered]', '::new(', 'Get-FileHash', '-FollowRelPath'):
            self.assertNotIn(unsupported, shared)
        for required in ("$env:APPDATA", "'credentials'", "'github-token'", 'ReparsePoint',
                         'SetAccessRuleProtection($true, $false)', 'FileMode]::CreateNew',
                         'FileShare]::Read', '$stream.GetAccessControl()', 'Read-Host', '-AsSecureString',
                         'ZeroFreeBSTR', '[Array]::Clear', 'SecurityProtocolType], 3072',
                         '$request.AllowAutoRedirect = $false', '$request.UseDefaultCredentials = $false',
                         "if ($hop -eq 0) { $request.Headers['Authorization']", '$hop -le 1',
                         '$inputStream.ReadTimeout', '$total -gt $MaximumBytes',
                         'Get-GitHubAsset $AgentUri $agentFile 268435456 120',
                         'Get-GitHubAsset $ArchiveUri $archiveFile 536870912 180',
                         'Windows NT 6.1', 'Administrator'):
            self.assertIn(required, script)
        self.assertLess(script.index('bootstrap-verify --archive'), script.index("Read-Host 'One-use HostLink invite token'"))
        self.assertLess(script.index('Verified ZIP executable differs'), script.index("Read-Host 'One-use HostLink invite token'"))
        self.assertNotIn('GetFileName($archiveUriObject.AbsolutePath)', script)
        self.assertIn('Get-GitHubCredential([bool]$Provision, [string]$EmbeddedToken)', script)
        # An unbound [string] argument becomes empty string in PowerShell,
        # so comparing against $null would break the normal hidden prompt.
        self.assertIn('if (-not [string]::IsNullOrEmpty($EmbeddedToken))', script)
        self.assertIn('if (-not [string]::IsNullOrEmpty($EmbeddedToken) -and $EmbeddedToken -cne $existing)', script)
        shell = SH.read_text()
        self.assertLess(shell.index('bootstrap-verify --archive'), shell.index("printf 'One-use HostLink invite token"))
        self.assertNotIn('archive_name=', shell)
        self.assertNotIn('--location', shell)


if __name__ == '__main__':
    unittest.main()
