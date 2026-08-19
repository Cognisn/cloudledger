"""
Tests for the AWS Organisation / control-tower flow.

Covers the org questions added to `prompt_for_account_config`, the
entry-time management-account follow-up decision, the CSV org columns,
and the ScanMetadata construction that carries the org fields.

Uses Australian English in all documentation and comments.
"""

from datetime import datetime, UTC

import pytest

from cloudledger.database.models import ScanMetadata
from cloudledger.database.operations import DatabaseOperations
from cloudledger.database.schema import DatabaseSchema
from cloudledger.scanner import cli
from cloudledger.scanner.cli import _build_scan_metadata, _decide_management_follow_up
from cloudledger.scanner.credential_manager import (
    AccountConfig,
    AWSCredentials,
    CredentialManager,
)
from cloudledger.scanner.csv_input import CSVAccountReader, CSVInputError


def _feed_input(monkeypatch, answers):
    """Feed scripted answers to builtins.input, recording each prompt asked."""
    it = iter(answers)
    calls = []

    def fake_input(prompt=""):
        calls.append(prompt)
        return next(it)

    monkeypatch.setattr("builtins.input", fake_input)
    return calls


def _stub_credentials(monkeypatch):
    """Avoid masked getpass prompts consuming the scripted input() answers."""
    monkeypatch.setattr("getpass.getpass", lambda prompt="": "secret")


# ---------------------------------------------------------------------------
# (a) prompt_for_account_config org questions
# ---------------------------------------------------------------------------


class TestPromptForAccountConfigOrgQuestions:
    def test_member_and_management_account(self, monkeypatch):
        _stub_credentials(monkeypatch)
        calls = _feed_input(
            monkeypatch,
            [
                "Test Account",  # account name
                "123456789012",  # account number
                "AKIAEXAMPLE",  # access key id
                "skip",  # prowler level
                "",  # tags
                "y",  # org member?
                "y",  # is management account?
            ],
        )

        account = CredentialManager.prompt_for_account_config()

        assert (
            account.org_member,
            account.is_management_account,
            account.management_account_id,
            account.management_account_name,
        ) == (True, True, None, None)
        assert len(calls) == 7

    def test_member_and_non_management_account(self, monkeypatch):
        _stub_credentials(monkeypatch)
        _feed_input(
            monkeypatch,
            [
                "Test Account",
                "123456789012",
                "AKIAEXAMPLE",
                "skip",
                "",
                "y",  # org member?
                "n",  # is management account?
                "Mgmt",  # management account name
                "999999999999",  # management account id
            ],
        )

        account = CredentialManager.prompt_for_account_config()

        assert (
            account.org_member,
            account.is_management_account,
            account.management_account_id,
            account.management_account_name,
        ) == (True, False, "999999999999", "Mgmt")

    def test_management_account_name_reprompts_on_blank(self, monkeypatch):
        _stub_credentials(monkeypatch)
        calls = _feed_input(
            monkeypatch,
            [
                "Test Account",
                "123456789012",
                "AKIAEXAMPLE",
                "skip",
                "",
                "y",  # org member?
                "n",  # is management account?
                "",  # blank management account name -> re-prompt
                "Mgmt",  # management account name
                "999999999999",  # management account id
            ],
        )

        account = CredentialManager.prompt_for_account_config()

        assert (
            account.org_member,
            account.is_management_account,
            account.management_account_id,
            account.management_account_name,
        ) == (True, False, "999999999999", "Mgmt")
        assert len(calls) == 10

    def test_non_member_account(self, monkeypatch):
        _stub_credentials(monkeypatch)
        _feed_input(
            monkeypatch,
            [
                "Test Account",
                "123456789012",
                "AKIAEXAMPLE",
                "skip",
                "",
                "n",  # org member? -> No
            ],
        )

        account = CredentialManager.prompt_for_account_config()

        assert (
            account.org_member,
            account.is_management_account,
            account.management_account_id,
            account.management_account_name,
        ) == (False, None, None, None)

    def test_include_org_questions_false_asks_nothing_extra(self, monkeypatch):
        _stub_credentials(monkeypatch)
        calls = _feed_input(
            monkeypatch,
            [
                "Test Account",
                "123456789012",
                "AKIAEXAMPLE",
                "skip",
                "",
            ],
        )

        account = CredentialManager.prompt_for_account_config(
            include_org_questions=False
        )

        # Exactly the five base prompts were consumed - a StopIteration would
        # have been raised by fake_input had any org prompt been asked.
        assert len(calls) == 5
        assert (
            account.org_member,
            account.is_management_account,
            account.management_account_id,
            account.management_account_name,
        ) == (None, None, None, None)

    def test_management_account_id_reprompts_on_invalid(self, monkeypatch):
        _stub_credentials(monkeypatch)
        calls = _feed_input(
            monkeypatch,
            [
                "Test Account",
                "123456789012",
                "AKIAEXAMPLE",
                "skip",
                "",
                "y",  # org member?
                "n",  # is management account?
                "Mgmt",  # management account name
                "not-a-number",  # invalid id
                "123",  # still invalid
                "999999999999",  # valid id
            ],
        )

        account = CredentialManager.prompt_for_account_config()

        assert account.management_account_id == "999999999999"
        assert len(calls) == 11


# ---------------------------------------------------------------------------
# (b) _decide_management_follow_up
# ---------------------------------------------------------------------------


def _seed_db(tmp_path, account_number: str = "123456789012") -> str:
    path = str(tmp_path / "org_flow.db")
    DatabaseSchema(path).initialise_database()
    ops = DatabaseOperations(path)
    ops.insert_scan_metadata(
        ScanMetadata(
            scan_id="s1",
            account_name="a",
            account_number=account_number,
            scan_timestamp=datetime.now(UTC),
            regions_scanned=["ap-southeast-2"],
            scan_status="completed",
        )
    )
    return path


def _member_account(management_account_id: str, management_account_name: str = "Mgmt"):
    return AccountConfig(
        account_name="Member Account",
        account_number="111111111111",
        credentials=AWSCredentials(
            access_key_id="AKIAEXAMPLE", secret_access_key="secret"
        ),
        org_member=True,
        is_management_account=False,
        management_account_id=management_account_id,
        management_account_name=management_account_name,
    )


class TestDecideManagementFollowUp:
    def test_unseen_management_account_offers_scan(self, monkeypatch, tmp_path, capsys):
        db_path = _seed_db(tmp_path, account_number="222222222222")
        db_ops = DatabaseOperations(db_path)
        account = _member_account(management_account_id="999999999999")

        _feed_input(monkeypatch, ["y"])

        decision = _decide_management_follow_up(account, db_ops)

        assert decision is True
        output = capsys.readouterr().out
        assert "No scan of management account" in output

    def test_seen_management_account_reports_last_scanned(
        self, monkeypatch, tmp_path, capsys
    ):
        db_path = _seed_db(tmp_path, account_number="999999999999")
        db_ops = DatabaseOperations(db_path)
        account = _member_account(management_account_id="999999999999")

        _feed_input(monkeypatch, ["n"])

        decision = _decide_management_follow_up(account, db_ops)

        assert decision is False
        output = capsys.readouterr().out
        assert "last scanned" in output


# ---------------------------------------------------------------------------
# (c) CSV org columns
# ---------------------------------------------------------------------------


class TestCSVOrgColumns:
    def _write_csv(self, tmp_path, extra_row: dict) -> str:
        import csv

        path = tmp_path / "accounts.csv"
        fieldnames = [
            "account_name",
            "account_number",
            "access_key_id",
            "secret_access_key",
            "session_token",
            "org_member",
            "is_management_account",
            "management_account_id",
            "management_account_name",
        ]
        row = {
            "account_name": "Test Account",
            "account_number": "123456789012",
            "access_key_id": "AKIAEXAMPLE",
            "secret_access_key": "secretkey",
            "session_token": "sessiontoken",
        }
        row.update(extra_row)
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerow(row)
        return str(path)

    def test_parses_org_columns(self, tmp_path):
        csv_path = self._write_csv(
            tmp_path,
            {
                "org_member": "yes",
                "is_management_account": "no",
                "management_account_id": "999999999999",
                "management_account_name": "Mgmt",
            },
        )

        accounts = CSVAccountReader(csv_path).read_accounts()

        assert len(accounts) == 1
        account = accounts[0]
        assert account.org_member is True
        assert account.is_management_account is False
        assert account.management_account_id == "999999999999"
        assert account.management_account_name == "Mgmt"

    def test_invalid_boolean_raises(self, tmp_path):
        csv_path = self._write_csv(tmp_path, {"org_member": "maybe"})

        reader = CSVAccountReader(csv_path)
        with pytest.raises(CSVInputError):
            reader.read_accounts()


# ---------------------------------------------------------------------------
# (d) _build_scan_metadata carries the org fields
# ---------------------------------------------------------------------------


class TestBuildScanMetadata:
    def test_metadata_carries_org_fields(self):
        account = AccountConfig(
            account_name="Test Account",
            account_number="123456789012",
            credentials=AWSCredentials(
                access_key_id="AKIAEXAMPLE", secret_access_key="secret"
            ),
            prowler_level="2",
            org_member=True,
            is_management_account=True,
            management_account_id=None,
            management_account_name=None,
        )
        start_time = datetime.now(UTC)

        metadata = _build_scan_metadata(account, "scan-1", start_time)

        assert isinstance(metadata, ScanMetadata)
        assert metadata.scan_id == "scan-1"
        assert metadata.account_name == "Test Account"
        assert metadata.account_number == "123456789012"
        assert metadata.prowler_level == "2"
        assert metadata.org_member is True
        assert metadata.is_management_account is True
        assert metadata.management_account_id is None
        assert metadata.management_account_name is None

    def test_metadata_carries_management_member_fields(self):
        account = AccountConfig(
            account_name="Member Account",
            account_number="111111111111",
            credentials=AWSCredentials(
                access_key_id="AKIAEXAMPLE", secret_access_key="secret"
            ),
            org_member=True,
            is_management_account=False,
            management_account_id="999999999999",
            management_account_name="Mgmt",
        )
        start_time = datetime.now(UTC)

        metadata = _build_scan_metadata(account, "scan-2", start_time)

        assert metadata.org_member is True
        assert metadata.is_management_account is False
        assert metadata.management_account_id == "999999999999"
        assert metadata.management_account_name == "Mgmt"


# ---------------------------------------------------------------------------
# (e) End-to-end management-queue mechanics
#
# Promoted from the reviewer's throwaway probe (see task-4-review.md) into
# the permanent suite, per the Task 4 review's ruling. Drives `cli._run_scan`
# end-to-end with `input()` and `CredentialManager.prompt_for_credentials`
# monkeypatched, and `cli._scan_account` stubbed out, so the queue mechanics
# (append to the back of the queue, dedupe against the remaining queue by
# account number, deferred credential prompt firing only after a successful
# scan) are pinned down against regression.
# ---------------------------------------------------------------------------


class TestManagementQueueEndToEnd:
    @staticmethod
    def _stub_prompt_for_credentials(monkeypatch):
        """Count-recording stub - avoids AWS calls and getpass masking noise."""
        calls = []

        def fake_prompt_for_credentials():
            calls.append(1)
            return AWSCredentials(
                access_key_id="AKIAEXAMPLE", secret_access_key="secret"
            )

        monkeypatch.setattr(
            CredentialManager, "prompt_for_credentials", fake_prompt_for_credentials
        )
        return calls

    @staticmethod
    def _stub_scan_account(monkeypatch, raise_for=None):
        """Recording stub for `_scan_account`; raises for the given account number."""
        scanned = []

        def fake_scan_account(account, db_ops, regions, cli_tags=None):
            scanned.append(account)
            if raise_for is not None and account.account_number == raise_for:
                raise RuntimeError("simulated scan failure")

        monkeypatch.setattr(cli, "_scan_account", fake_scan_account)
        return scanned

    def test_management_queue_end_to_end(self, monkeypatch, tmp_path):
        credential_calls = self._stub_prompt_for_credentials(monkeypatch)
        scanned = self._stub_scan_account(monkeypatch)

        answers = [
            # Account A - org member, non-management, mgmt id unseen
            "Account A",
            "111111111111",
            "skip",
            "",
            "y",
            "n",
            "Mgmt",
            "999999999999",
            "y",  # follow-up? (unseen management account)
            "y",  # scan another account?
            # Account B - same management id, mgmt still unseen (scanning
            # hasn't started yet, so the ledger has no record of it)
            "Account B",
            "222222222222",
            "skip",
            "",
            "y",
            "n",
            "Mgmt",
            "999999999999",
            "y",  # follow-up? (still unseen)
            "n",  # scan another account?
            # Management follow-up scan, queued after A's scan completes
            "skip",  # prowler level
        ]
        calls = _feed_input(monkeypatch, answers)

        db_path = str(tmp_path / "queue.db")
        cli._run_scan(db_path, csv=None, regions=None)

        # (a) the management scan runs after the first account's scan -
        # appended to the back of the queue, not immediately next
        assert [a.account_number for a in scanned] == [
            "111111111111",
            "222222222222",
            "999999999999",
        ]

        # (b) queued config has org_member/is_management_account set from the
        # recorded management details, and no org questions were re-asked
        mgmt_scanned = scanned[2]
        assert mgmt_scanned.org_member is True
        assert mgmt_scanned.is_management_account is True
        org_member_prompts = [c for c in calls if "member of an AWS Organisation" in c]
        assert len(org_member_prompts) == 2  # A's and B's own setup only

        # (c) same-management-id dedupe: only one scan carries the
        # management account number, despite both A and B requesting a
        # follow-up - B's follow-up did not queue a duplicate
        assert [a.account_number for a in scanned].count("999999999999") == 1

        # Credentials were sought for A, B, and the queued management scan -
        # never suppressed or duplicated
        assert len(credential_calls) == 3

    def test_failed_first_scan_does_not_trigger_credential_prompt(
        self, monkeypatch, tmp_path
    ):
        credential_calls = self._stub_prompt_for_credentials(monkeypatch)
        scanned = self._stub_scan_account(monkeypatch, raise_for="111111111111")

        answers = [
            "Account A",
            "111111111111",
            "skip",
            "",
            "n",  # not an org member - no follow-up possible
            "n",  # scan another account?
        ]
        calls = _feed_input(monkeypatch, answers)

        db_path = str(tmp_path / "queue_failed.db")
        cli._run_scan(db_path, csv=None, regions=None)

        # (d) a failed first scan never reaches the deferred credential
        # prompt - the follow-up block sits inside the `try:` after
        # `_scan_account` returns, and an exception jumps straight past it
        assert len(scanned) == 1
        assert len(credential_calls) == 1  # only account A's own setup
        assert len(calls) == len(answers)  # no extra input() calls consumed


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
