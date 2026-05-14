"""Tests for ``ioc_tool.core.llm`` — local Ollama summarisation.

Every test mocks the ``POST /api/generate`` endpoint with the
``responses`` lib so the suite never touches a live Ollama server.

Contracts under test (all driven by ``docs/ROADMAP.md`` LLM summary item):

* ``summarize()`` returns text on a clean 200 response and never raises
* All failure modes (connection error, timeout, non-200, malformed
  JSON, missing ``response`` field) return ``None``
* Env-based ``OLLAMA_MODEL`` and ``OLLAMA_BASE_URL`` overrides are
  honoured by the outgoing request
* ``_build_prompt`` produces a string containing the IOC value, final
  score, and at least one source name — so the verdict is grounded in
  the actual data
"""

from __future__ import annotations

import json
from typing import Any, Dict

import pytest
import requests
import responses

from ioc_tool.core import llm


def _sample_result() -> Dict[str, Any]:
    """A representative enrichment result the LLM might be asked to summarise."""
    return {
        "ioc": "1.2.3.4",
        "type": "ip",
        "final_score": 85,
        "modules": {
            "VirusTotal": {
                "score": 5,
                "data": {
                    "last_analysis_stats": {
                        "malicious": 5,
                        "harmless": 80,
                        "suspicious": 0,
                        "undetected": 15,
                    }
                },
            },
            "AbuseIPDB": {
                "score": 95,
                "data": {
                    "abuseConfidenceScore": 95,
                    "usageType": "Data Center",
                },
            },
            "URLhaus": {
                "score": 95,
                "data": {"threat": "malware_download", "tags": ["Emotet"]},
            },
        },
    }


# ---------------------------------------------------------------------------
# summarize() — happy path
# ---------------------------------------------------------------------------


@responses.activate
def test_summarize_returns_text_on_success() -> None:
    """A clean 200 with a ``response`` field returns the model's text."""
    responses.add(
        responses.POST,
        "http://localhost:11434/api/generate",
        json={"response": "High risk IP backed by VT + AbuseIPDB + URLhaus.", "done": True},
        status=200,
    )
    out = llm.summarize(_sample_result())
    assert out == "High risk IP backed by VT + AbuseIPDB + URLhaus."


@responses.activate
def test_summarize_strips_whitespace() -> None:
    """Leading/trailing whitespace and newlines are stripped from the verdict."""
    responses.add(
        responses.POST,
        "http://localhost:11434/api/generate",
        json={"response": "  text\n\n", "done": True},
        status=200,
    )
    out = llm.summarize(_sample_result())
    assert out == "text"


# ---------------------------------------------------------------------------
# summarize() — failure modes (must return None, never raise)
# ---------------------------------------------------------------------------


def test_summarize_returns_none_on_connection_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """A connection error (Ollama not running) returns ``None`` cleanly."""
    def _boom(*_args: Any, **_kwargs: Any) -> Any:
        raise requests.exceptions.ConnectionError("nobody home")

    monkeypatch.setattr(requests, "post", _boom)
    assert llm.summarize(_sample_result()) is None


@responses.activate
def test_summarize_returns_none_on_non_200() -> None:
    """A 5xx response from Ollama returns ``None``."""
    responses.add(
        responses.POST,
        "http://localhost:11434/api/generate",
        json={"error": "model not found"},
        status=500,
    )
    assert llm.summarize(_sample_result()) is None


def test_summarize_returns_none_on_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    """A request timeout returns ``None``."""
    def _timeout(*_args: Any, **_kwargs: Any) -> Any:
        raise requests.exceptions.Timeout("slow")

    monkeypatch.setattr(requests, "post", _timeout)
    assert llm.summarize(_sample_result()) is None


@responses.activate
def test_summarize_returns_none_on_malformed_json() -> None:
    """A 200 response with no JSON body returns ``None``."""
    responses.add(
        responses.POST,
        "http://localhost:11434/api/generate",
        body="not-json-just-text",
        status=200,
    )
    assert llm.summarize(_sample_result()) is None


@responses.activate
def test_summarize_returns_none_when_response_field_missing() -> None:
    """A 200 JSON body lacking the ``response`` key returns ``None``."""
    responses.add(
        responses.POST,
        "http://localhost:11434/api/generate",
        json={"done": True},
        status=200,
    )
    assert llm.summarize(_sample_result()) is None


# ---------------------------------------------------------------------------
# summarize() — env overrides
# ---------------------------------------------------------------------------


@responses.activate
def test_summarize_uses_env_model_override(monkeypatch: pytest.MonkeyPatch) -> None:
    """``OLLAMA_MODEL`` env var flows into the outgoing request body."""
    monkeypatch.setenv("OLLAMA_MODEL", "mistral")
    responses.add(
        responses.POST,
        "http://localhost:11434/api/generate",
        json={"response": "ok"},
        status=200,
    )
    out = llm.summarize(_sample_result())
    assert out == "ok"
    assert len(responses.calls) == 1
    body = json.loads(responses.calls[0].request.body)
    assert body["model"] == "mistral"


@responses.activate
def test_summarize_uses_env_base_url_override(monkeypatch: pytest.MonkeyPatch) -> None:
    """``OLLAMA_BASE_URL`` env var routes the request to the configured host."""
    monkeypatch.setenv("OLLAMA_BASE_URL", "http://lab:11434")
    responses.add(
        responses.POST,
        "http://lab:11434/api/generate",
        json={"response": "via lab"},
        status=200,
    )
    out = llm.summarize(_sample_result())
    assert out == "via lab"
    assert responses.calls[0].request.url.startswith("http://lab:11434/")


@responses.activate
def test_summarize_explicit_args_override_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Explicit ``model`` / ``base_url`` arguments win over env vars."""
    monkeypatch.setenv("OLLAMA_MODEL", "mistral")
    monkeypatch.setenv("OLLAMA_BASE_URL", "http://ignored:11434")
    responses.add(
        responses.POST,
        "http://chosen:11434/api/generate",
        json={"response": "explicit win"},
        status=200,
    )
    out = llm.summarize(
        _sample_result(),
        model="llama3:custom",
        base_url="http://chosen:11434",
    )
    assert out == "explicit win"
    body = json.loads(responses.calls[0].request.body)
    assert body["model"] == "llama3:custom"


# ---------------------------------------------------------------------------
# _build_prompt — private helper, exposed for unit testing
# ---------------------------------------------------------------------------


def test_build_prompt_includes_score_and_sources() -> None:
    """The prompt contains the IOC value, final score, and at least one source."""
    prompt = llm._build_prompt(_sample_result())
    assert "1.2.3.4" in prompt
    assert "85" in prompt
    # At least one source name must surface so the verdict is grounded.
    assert (
        "VirusTotal" in prompt
        or "AbuseIPDB" in prompt
        or "URLhaus" in prompt
    )
    # Must explicitly ask for the verdict and constrain output shape
    assert "Verdict:" in prompt
    assert "2-3 sentence" in prompt


def test_build_prompt_handles_missing_modules() -> None:
    """An empty modules dict still produces a well-formed prompt."""
    prompt = llm._build_prompt({"ioc": "0.0.0.0", "type": "ip", "final_score": 0, "modules": {}})
    assert "0.0.0.0" in prompt
    assert "no source signals" in prompt.lower()


def test_summarize_non_dict_input_returns_none() -> None:
    """A non-dict ``result`` argument returns ``None`` without raising."""
    assert llm.summarize(None) is None  # type: ignore[arg-type]
    assert llm.summarize("not-a-dict") is None  # type: ignore[arg-type]
