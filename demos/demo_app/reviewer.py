"""
Anthropic LLM reviewer callback for permit0 AgentReviewer.

This module provides the Python-side LLM call that the Rust AgentReviewer
invokes via the callback bridge. The Rust side handles all the reviewer
logic (skip conditions, prompt construction, response parsing, confidence
gating). This function just sends the prompt and returns raw text.
"""
from __future__ import annotations

import os

import anthropic


# Lazy-initialized client
_client: anthropic.Anthropic | None = None


def get_client() -> anthropic.Anthropic:
    global _client
    if _client is None:
        _client = anthropic.Anthropic()
    return _client


def anthropic_review(prompt: str) -> str:
    """
    LLM reviewer callback for permit0 AgentReviewer.

    Called by the Rust engine when a MEDIUM-tier tool call needs LLM review.
    Returns the raw text response — Rust handles parsing and confidence gating.
    """
    client = get_client()
    message = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=1024,
        messages=[{"role": "user", "content": prompt}],
    )
    return message.content[0].text
