import pytest

from phishguard.features import FEATURE_NAMES, extract_features, feature_vector, shannon_entropy


def test_vector_length_matches_names():
    assert len(feature_vector("https://example.com/a?b=1")) == len(FEATURE_NAMES) == 37


def test_values_basic():
    f = extract_features("https://www.example.com/a/b?x=1&y=2")
    assert f["is_https"] == 1 and f["path_depth"] == 2 and f["param_count"] == 2
    assert f["subdomain_count"] == 1 and f["is_ip_host"] == 0


def test_ip_and_at():
    f = extract_features("http://10.0.0.1@evil.com/")
    assert f["at_symbol"] == 1
    assert extract_features("http://10.0.0.1/")["is_ip_host"] == 1


def test_scheme_added_when_missing():
    assert extract_features("example.com")["is_https"] == 0


def test_entropy():
    assert shannon_entropy("") == 0
    assert shannon_entropy("aaaa") == 0
    assert shannon_entropy("abcd") == pytest.approx(2.0)


def test_unparsable():
    with pytest.raises(ValueError):
        extract_features("")
