import pytest

from invariant.config import Config
from invariant.engine import Engine


@pytest.fixture
def cfg():
    return Config.load()


@pytest.fixture
def run(cfg):
    """Run events through a fresh engine and return the alerts."""

    def _run(events, config=None):
        eng = Engine(config or cfg)
        return eng.run(events)

    return _run


def rule_ids(alerts):
    return {a.rule_id for a in alerts}


# Fake credentials are assembled at runtime so no key-shaped literal is committed
# (keeps GitHub push protection and secret scanners quiet).
def fake_anthropic_key():
    return "sk-ant-" + "api03-" + "Ab1_" * 23 + "x" + "AA"


def fake_openai_key():
    return "sk-" + "proj-" + "A1b2C3d4E5f6G7h8I9j0" + "T3Blbk" + "FJ" + "K1l2M3n4O5p6Q7r8S9t0"


def fake_hf_token():
    return "hf" + "_" + "AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGh"


def fake_google_key():
    return "AI" + "za" + "Sy" + "D" * 33
