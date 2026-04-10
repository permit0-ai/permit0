"""Tests for permit0 Python bindings — mirrors Rust integration tests."""

import os
import json
import pytest

import permit0
from permit0 import (
    Permission,
    Tier,
    Engine,
    EngineBuilder,
    DecisionResult,
    RiskScore,
    NormAction,
)

# ── Fixtures ──

PACKS_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "..", "packs")

STRIPE_NORM_YAML = os.path.join(PACKS_DIR, "stripe", "normalizers", "charges_create.yaml")
STRIPE_RISK_YAML = os.path.join(PACKS_DIR, "stripe", "risk_rules", "charge.yaml")
BASH_NORM_YAML = os.path.join(PACKS_DIR, "bash", "normalizers", "shell.yaml")
BASH_RISK_YAML = os.path.join(PACKS_DIR, "bash", "risk_rules", "shell.yaml")


@pytest.fixture
def engine():
    """Build an engine from packs directory (mirrors build_test_engine in Rust)."""
    return Engine.from_packs(PACKS_DIR)


@pytest.fixture
def builder_engine():
    """Build an engine using the builder API with YAML files."""
    builder = EngineBuilder()
    for path in [STRIPE_NORM_YAML, BASH_NORM_YAML]:
        with open(path) as f:
            builder.install_normalizer_yaml(f.read())
    for path in [STRIPE_RISK_YAML, BASH_RISK_YAML]:
        with open(path) as f:
            builder.install_risk_rule_yaml(f.read())
    return builder.build()


# ── Permission enum tests ──


class TestPermission:
    def test_variants_exist(self):
        assert Permission.Allow is not None
        assert Permission.Human is not None
        assert Permission.Deny is not None

    def test_str_representation(self):
        assert str(Permission.Allow) == "allow"
        assert str(Permission.Human) == "human"
        assert str(Permission.Deny) == "deny"

    def test_repr(self):
        assert repr(Permission.Allow) == "Permission.Allow"

    def test_equality(self):
        assert Permission.Allow == Permission.Allow
        assert Permission.Allow != Permission.Deny


# ── Tier enum tests ──


class TestTier:
    def test_variants_exist(self):
        assert Tier.Minimal is not None
        assert Tier.Low is not None
        assert Tier.Medium is not None
        assert Tier.High is not None
        assert Tier.Critical is not None

    def test_str_representation(self):
        assert str(Tier.Minimal) == "minimal"
        assert str(Tier.Critical) == "critical"


# ── Engine.from_packs tests ──


class TestEngineFromPacks:
    def test_engine_creates(self, engine):
        assert engine is not None
        assert repr(engine) == "Engine()"

    def test_safe_bash_allows(self, engine):
        result = engine.get_permission("bash", {"command": "ls -la"})
        assert result.permission == Permission.Allow
        assert result.source == "Scorer"

    def test_dangerous_bash_denies(self, engine):
        result = engine.get_permission("bash", {"command": "echo data > /dev/sda"})
        assert result.permission == Permission.Deny
        assert result.risk_score is not None
        assert result.risk_score.blocked is True

    def test_stripe_low_charge_allows(self, engine):
        result = engine.get_permission(
            "http",
            {
                "method": "POST",
                "url": "https://api.stripe.com/v1/charges",
                "body": {"amount": 50, "currency": "usd"},
            },
        )
        assert result.permission == Permission.Allow
        assert result.risk_score is not None
        assert result.risk_score.tier == Tier.Minimal

    def test_stripe_crypto_currency_denies(self, engine):
        """Crypto currency triggers a gate → deny."""
        result = engine.get_permission(
            "http",
            {
                "method": "POST",
                "url": "https://api.stripe.com/v1/charges",
                "body": {"amount": 1000, "currency": "btc"},
            },
        )
        assert result.permission == Permission.Deny
        assert result.risk_score is not None
        assert result.risk_score.blocked is True

    def test_unknown_tool_returns_human(self, engine):
        """Unknown tools should get human-in-the-loop."""
        result = engine.get_permission("unknown_tool", {"some": "data"})
        assert result.permission == Permission.Human


# ── EngineBuilder tests ──


class TestEngineBuilder:
    def test_builder_creates_engine(self, builder_engine):
        assert builder_engine is not None

    def test_builder_engine_scores(self, builder_engine):
        result = builder_engine.get_permission("bash", {"command": "ls"})
        assert result.permission == Permission.Allow

    def test_builder_consumed_after_build(self):
        builder = EngineBuilder()
        with open(BASH_NORM_YAML) as f:
            builder.install_normalizer_yaml(f.read())
        with open(BASH_RISK_YAML) as f:
            builder.install_risk_rule_yaml(f.read())
        _engine = builder.build()
        # Builder should be consumed after build
        with pytest.raises(RuntimeError, match="already consumed"):
            builder.build()


# ── DecisionResult tests ──


class TestDecisionResult:
    def test_result_has_norm_action(self, engine):
        result = engine.get_permission("bash", {"command": "ls"})
        assert result.norm_action is not None
        assert isinstance(result.norm_action.action_type, str)
        assert isinstance(result.norm_action.channel, str)
        assert isinstance(result.norm_action.norm_hash, str)
        assert len(result.norm_action.norm_hash) == 16

    def test_result_has_risk_score(self, engine):
        result = engine.get_permission("bash", {"command": "ls"})
        assert result.risk_score is not None
        assert isinstance(result.risk_score.raw, float)
        assert isinstance(result.risk_score.score, int)
        assert 0.0 <= result.risk_score.raw <= 1.0
        assert 0 <= result.risk_score.score <= 100

    def test_norm_action_entities(self, engine):
        result = engine.get_permission(
            "http",
            {
                "method": "POST",
                "url": "https://api.stripe.com/v1/charges",
                "body": {"amount": 5000, "currency": "usd"},
            },
        )
        entities = result.norm_action.entities()
        assert isinstance(entities, dict)

    def test_repr(self, engine):
        result = engine.get_permission("bash", {"command": "ls"})
        r = repr(result)
        assert "DecisionResult" in r
        assert "permission=" in r


# ── check_json convenience method ──


class TestCheckJson:
    def test_check_json_basic(self, engine):
        payload = json.dumps(
            {
                "tool_name": "bash",
                "parameters": {"command": "ls"},
                "metadata": {},
            }
        )
        result = engine.check_json(payload)
        assert result.permission == Permission.Allow

    def test_check_json_invalid(self, engine):
        with pytest.raises(ValueError, match="invalid JSON"):
            engine.check_json("not json")


# ── Org domain parameter ──


class TestOrgDomain:
    def test_custom_org_domain(self, engine):
        result = engine.get_permission(
            "bash", {"command": "ls"}, org_domain="acme.com"
        )
        assert result.permission == Permission.Allow

    def test_default_org_domain(self, engine):
        # Should work without explicit org_domain
        result = engine.get_permission("bash", {"command": "ls"})
        assert result.permission == Permission.Allow
