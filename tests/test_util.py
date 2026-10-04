from __future__ import annotations

import pytest

from claimcheck import util


def test_registrable_domain_basic_and_multipart():
    assert util.registrable_domain("a.b.example.com") == "example.com"
    assert util.registrable_domain("api.foo.co.uk") == "foo.co.uk"
    assert util.registrable_domain("Example.COM.") == "example.com"
    assert util.registrable_domain("localhost") == "localhost"
    assert util.registrable_domain("10.0.0.1") == "10.0.0.1"


def test_domain_matches_is_suffix_on_label_boundary():
    assert util.domain_matches("o1.ingest.sentry.io", "sentry.io")
    assert util.domain_matches("sentry.io", "sentry.io")
    assert not util.domain_matches("notsentry.io", "sentry.io")
    assert not util.domain_matches("sentry.io.evil.com", "sentry.io")


def test_host_suffixes_stops_before_tld():
    assert list(util.host_suffixes("a.b.c.com")) == ["a.b.c.com", "b.c.com", "c.com"]


def test_redact_masks_sensitive_patterns():
    s = "mail me a@b.co id 123e4567-e89b-12d3-a456-426614174000 tok " + "A" * 40 + " n 1234567890123"
    out = util.redact_text(s)
    assert "a@b.co" not in out and "<email>" in out
    assert "<uuid>" in out and "<token>" in out and "<num>" in out


def test_unique_path_never_overwrites(tmp_path):
    p1 = util.unique_path(tmp_path, "x", ".txt")
    p1.write_text("a")
    p2 = util.unique_path(tmp_path, "x", ".txt")
    assert p1 != p2 and p2.name == "x-2.txt"


def test_atomic_write_replaces_content(tmp_path):
    p = tmp_path / "f.txt"
    util.atomic_write_text(p, "one")
    util.atomic_write_text(p, "two")
    assert p.read_text() == "two"
    assert [x.name for x in tmp_path.iterdir()] == ["f.txt"]  # no temp leftovers


@pytest.mark.parametrize("n,expected", [(0, "0 B"), (1536, "1.5 KB"), (5 * 1024**2, "5.0 MB")])
def test_human_bytes(n, expected):
    assert util.human_bytes(n) == expected


def test_slugify_and_expand_path(tmp_path):
    assert util.slugify(" My App! v2 ") == "my-app-v2"
    assert util.slugify("///") == "app"
    assert util.expand_path("sub/x", tmp_path) == str(tmp_path / "sub" / "x")
    assert util.expand_path("", tmp_path) == ""


def test_jload_tolerates_garbage():
    assert util.jload("{bad", default=[1]) == [1]
    assert util.jload(None, default={}) == {}
    assert util.jload('{"a":1}') == {"a": 1}
