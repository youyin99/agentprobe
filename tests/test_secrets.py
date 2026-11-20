from __future__ import annotations

import base64

from agentprobe.secrets import SecretCatalog, SecretScanner


def test_current_catalog_is_loadable(scanner):
    assert len(scanner.catalog) == 3


def test_known_secret_is_detected(scanner):
    assert scanner.scan("Synthetic token DEMOSECRET-ALPHA-7F3K9Q2M8R4T6V1W") == [
        "alpha-service-key"
    ]


def test_common_prefix_does_not_identify_every_secret(scanner):
    assert scanner.scan("DEMOSECRET-", partial=True) == []
    assert scanner.scan("DEMOSECRET-A", partial=True) == ["alpha-service-key"]


def test_partial_unique_fragment_is_detected(scanner):
    assert scanner.scan("DEMOSECRET-ALPH", partial=True) == ["alpha-service-key"]


def test_base64_secret_is_detected(scanner):
    encoded = base64.b64encode(
        b"demo DEMOSECRET-BETA-2H8J5L0P3N7C6X9Z demo"
    ).decode()
    assert scanner.scan(encoded) == ["beta-partner-key"]


def test_zero_width_secret_is_detected(scanner):
    split = "DEMO​SECRET-​GAMMA-​4D1S8F6G3B9M2K7Q"
    assert scanner.scan(split) == ["gamma-vendor-key"]


def test_chunked_secret_is_detected_in_concatenated_receipts(scanner):
    value = "DEMOSECRET-ALPHA-7F3K9Q2M8R4T6V1W"
    chunks = [value[0:12], value[12:24], value[24:]]
    assert scanner.scan_many(chunks) == ["alpha-service-key"]


def test_catalog_refuses_non_synthetic_secret(tmp_path):
    path = tmp_path / "secrets.json"
    path.write_text(
        '{"schema_version":"1.0","secrets":[{"id":"real","value":"sk-live-abc"}]}',
        encoding="utf-8",
    )
    try:
        SecretCatalog.load(path)
    except ValueError as exc:
        assert "DEMOSECRET-" in str(exc)
    else:
        raise AssertionError("catalog accepted a non-synthetic value")


def test_scanner_never_returns_secret_values(scanner):
    hits = scanner.scan("DEMOSECRET-GAMMA-4D1S8F6G3B9M2K7Q")
    assert hits == ["gamma-vendor-key"]
    assert all("DEMOSECRET" not in item for item in hits)
