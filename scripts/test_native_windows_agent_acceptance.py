"""Static guards for the source-exact Windows Agent acceptance harness."""
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parent.parent


class NativeWindowsAgentAcceptanceTest(unittest.TestCase):
    def harness_source(self) -> str:
        return (ROOT / "scripts" / "native_windows_agent_acceptance.ps1").read_text(
            encoding="utf-8"
        )

    def test_fixture_failure_reports_only_a_bounded_safe_substage(self) -> None:
        harness = self.harness_source()
        for stage in (
            "fixture-ed25519-keygen",
            "fixture-ed25519-private-acl",
            "fixture-public-key-material",
            "fixture-random-secret",
            "fixture-secret-private-acl",
            "fixture-config-serialization",
        ):
            self.assertIn("$script:Stage = '" + stage + "'", harness)
        self.assertIn("$failure = 'harness-failure-at-' + $script:Stage", harness)
        self.assertNotIn("$failure = $_.Exception.Message", harness)

    def test_windows_powershell_51_passes_an_explicit_empty_ssh_key_passphrase(self) -> None:
        harness = self.harness_source()
        self.assertIn("& $sshKeygen -q -t ed25519 -N '\"\"'", harness)
        self.assertNotIn("& $sshKeygen -q -t ed25519 -N ''", harness)

    def test_harness_resolves_updater_from_installed_agent_bin(self) -> None:
        harness = self.harness_source()
        updater = (ROOT / "crates" / "onec-agent" / "src" / "managed_update.rs").read_text(
            encoding="utf-8"
        )

        self.assertIn(
            "$updater = Join-Path $script:Root 'hostlink-agent\\bin\\Update-HostLink-Agent.ps1'",
            harness,
        )
        self.assertIn('root.join("hostlink-agent/bin")', updater)
        self.assertIn('"Update-HostLink-Agent.ps1"', updater)

    def test_root_cleanup_requires_fresh_root_sentinel_inventory_and_no_reparse(self) -> None:
        harness = self.harness_source()

        cleanup = harness[harness.index("if ($script:Success -and $script:RootAbsentAtStart") :]
        self.assertIn("$script:RootCreatedByThisRun", cleanup)
        self.assertIn("$null -ne $script:RootInventory", cleanup)
        self.assertIn("$script:RootSentinel", cleanup)
        self.assertIn("Assert-NotReparse $script:Root 'Install root during cleanup'", cleanup)
        inventory_proof = cleanup.index("ConvertTo-Json -InputObject (Get-RootInventory $script:Root)")
        sentinel_delete = cleanup.index("[IO.File]::Delete($script:RootSentinel)")
        root_delete = cleanup.index("[IO.Directory]::Delete($script:Root, $true)")
        self.assertLess(inventory_proof, sentinel_delete)
        self.assertLess(sentinel_delete, root_delete)
        self.assertIn("$script:RootAbsentAtStart = $true", harness)

    def test_pass_is_emitted_only_after_cleanup_and_receipt(self) -> None:
        harness = self.harness_source()

        self.assertGreater(harness.index("if ($script:Success) {\n    Write-Output ('PASS source_sha="), harness.index("finally {"))
        self.assertLess(harness.index("Write-Receipt $(if ($script:Success)"), harness.index("if ($script:Success) {\n    Write-Output ('PASS source_sha="))
        self.assertIn("if ($script:ReceiptWritten) { Write-Output 'PASS receipt=written-private' }", harness)

    def test_non_admin_file_acl_uses_built_in_icacls_and_verifies_the_dacl(self) -> None:
        harness = self.harness_source()
        self.assertIn("$icacls = Join-Path $env:WINDIR 'System32\\icacls.exe'", harness)
        self.assertIn("'/inheritance:r' '/grant:r'", harness)
        self.assertIn("$acl.AreAccessRulesProtected", harness)
        self.assertIn("$sid -eq 'S-1-5-18'", harness)
        self.assertIn("$owner.Equals($identity.User)", harness)
        self.assertNotIn("Set-Acl -LiteralPath", harness)

    def test_receipt_is_acl_restricted_before_content_and_failure_is_path_free(self) -> None:
        harness = self.harness_source()
        receipt = harness[harness.index("function Write-Receipt") : harness.index("$failure = ''")]

        create_empty = receipt.index("[IO.FileMode]::CreateNew")
        close_empty = receipt.index("$stream.Dispose()")
        set_private_acl = receipt.index("Set-PrivateFile $script:ReceiptPath")
        check_reparse = receipt.index("Assert-NotReparse $script:ReceiptPath 'ReceiptFile before write'")
        check_owner = receipt.index("$receiptOwner.Equals($currentUser)")
        reopen_exclusive = receipt.index("[IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::None")
        write_content = receipt.index("$stream.Write($bytes, 0, $bytes.Length)")
        self.assertLess(create_empty, close_empty)
        self.assertLess(close_empty, set_private_acl)
        self.assertLess(set_private_acl, check_reparse)
        self.assertLess(check_reparse, check_owner)
        self.assertLess(check_owner, reopen_exclusive)
        self.assertLess(reopen_exclusive, write_content)
        failed_write_cleanup = receipt[receipt.index("if ($created -and -not $complete") :]
        self.assertIn("if ($cleanupInfo.Length -eq 0)", failed_write_cleanup)
        self.assertIn("$failure = 'harness-failure-at-' + $script:Stage", harness)
        self.assertNotIn("$failure = $_.Exception.Message", harness)

    def test_execution_policy_override_is_process_local_and_rejects_group_policy(self) -> None:
        harness = self.harness_source()
        documentation = (ROOT / "docs" / "native-windows-agent-acceptance.md").read_text(
            encoding="utf-8"
        )

        self.assertIn("Get-ExecutionPolicy -Scope MachinePolicy", harness)
        self.assertIn("Get-ExecutionPolicy -Scope UserPolicy", harness)
        self.assertIn("$machinePolicy -eq 'Undefined'", harness)
        self.assertIn("$userPolicy -eq 'Undefined'", harness)
        self.assertNotIn("$executionPolicies.MachinePolicy", harness)
        self.assertIn("-ExecutionPolicy Bypass", documentation)
        self.assertIn("do not change LocalMachine, CurrentUser, or Group Policy", documentation)

    def test_inventory_comparison_excludes_temporary_archive(self) -> None:
        harness = self.harness_source()

        stage_archive = harness.index("[IO.File]::Copy($archivePath, $stagedArchive, $false)")
        remove_archive = harness.index("[IO.File]::Delete($stagedArchive)")
        compare_inventory = harness.index("$afterUpdate = Get-RootInventory $script:Root")
        self.assertLess(stage_archive, remove_archive)
        self.assertLess(remove_archive, compare_inventory)

    def test_installer_nonzero_exit_cannot_be_treated_as_success(self) -> None:
        harness = self.harness_source()

        self.assertIn("Assert-Condition ($installResult.exit_code -eq 0)", harness)
        self.assertIn("$code = $LASTEXITCODE", harness)


if __name__ == "__main__":
    unittest.main()
