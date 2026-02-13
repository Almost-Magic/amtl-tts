"""
AMTL TTS Engine — Unified text-to-speech wrapper.

ELAINE's ElevenLabs voice (voice_id XQanfahzbl1YiUlZi5NW) is her PRIMARY voice.
These local models (Kokoro, MeloTTS) are for non-ELAINE TTS and local fallback only.
"""

import asyncio
import os
import tempfile
from pathlib import Path

import httpx

# ---------------------------------------------------------------------------
# ELAINE configuration
# ---------------------------------------------------------------------------
ELAINE_VOICE_ID = "XQanfahzbl1YiUlZi5NW"
ELEVENLABS_BASE_URL = "https://api.elevenlabs.io/v1"
ELEVENLABS_MODEL = "eleven_multilingual_v2"

# ---------------------------------------------------------------------------
# Lazy-loaded engine singletons
# ---------------------------------------------------------------------------
_kokoro_pipeline = None
_melo_model = None
_melo_speaker_ids = None


def _get_kokoro():
    """Lazy-load Kokoro pipeline."""
    global _kokoro_pipeline
    if _kokoro_pipeline is None:
        from kokoro import KPipeline
        _kokoro_pipeline = KPipeline(lang_code="a")
    return _kokoro_pipeline


def _get_melo():
    """Lazy-load MeloTTS model and speaker IDs."""
    global _melo_model, _melo_speaker_ids
    if _melo_model is None:
        from melo.api import TTS
        _melo_model = TTS(language="EN", device="auto")
        _melo_speaker_ids = _melo_model.hps.data.spk2id
    return _melo_model, _melo_speaker_ids


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def speak_as_elaine(
    text: str,
    output_path: str | None = None,
) -> bytes:
    """Speak as ELAINE using ElevenLabs (primary) with Kokoro fallback.

    Returns raw audio bytes (mp3 from ElevenLabs, wav from Kokoro fallback).
    If *output_path* is provided the audio is also written to that file.
    """
    api_key = os.environ.get("ELEVENLABS_API_KEY")

    if api_key:
        audio = await _elevenlabs_tts(text, api_key)
    else:
        # Fallback to Kokoro when no API key is available
        audio = _kokoro_generate(text)

    if output_path:
        Path(output_path).write_bytes(audio)

    return audio


def speak(
    text: str,
    engine: str = "kokoro",
    voice: str = "af_heart",
    output_path: str | None = None,
) -> bytes:
    """Local English TTS via Kokoro (default) or MeloTTS.

    Args:
        text: The text to synthesise.
        engine: ``"kokoro"`` or ``"melo"``.
        voice: Kokoro voice name (ignored for melo).
        output_path: Optional file path to write audio to.

    Returns:
        Raw WAV audio bytes.

    Raises:
        ValueError: If *engine* is not recognised.
    """
    if engine == "kokoro":
        audio = _kokoro_generate(text, voice=voice)
    elif engine == "melo":
        audio = _melo_generate(text)
    else:
        raise ValueError(f"Unknown engine: {engine!r}. Use 'kokoro' or 'melo'.")

    if output_path:
        Path(output_path).write_bytes(audio)

    return audio


def speak_multilingual(
    text: str,
    language: str = "EN",
    output_path: str | None = None,
) -> bytes:
    """Multilingual TTS via MeloTTS.

    Args:
        text: The text to synthesise.
        language: Language code (e.g. ``"EN"``).
        output_path: Optional file path to write audio to.

    Returns:
        Raw WAV audio bytes.
    """
    audio = _melo_generate(text, language=language)
    if output_path:
        Path(output_path).write_bytes(audio)
    return audio


def health_check() -> dict:
    """Return availability status of each TTS engine."""
    result = {}

    # Kokoro
    try:
        _get_kokoro()
        result["kokoro"] = True
    except Exception:
        result["kokoro"] = False

    # MeloTTS
    try:
        _get_melo()
        result["melo"] = True
    except Exception:
        result["melo"] = False

    # ElevenLabs — available if API key is set
    result["elevenlabs"] = bool(os.environ.get("ELEVENLABS_API_KEY"))

    return result


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


async def _elevenlabs_tts(text: str, api_key: str) -> bytes:
    """Call the ElevenLabs text-to-speech API."""
    url = f"{ELEVENLABS_BASE_URL}/text-to-speech/{ELAINE_VOICE_ID}"
    headers = {
        "xi-api-key": api_key,
        "Content-Type": "application/json",
    }
    payload = {
        "text": text,
        "model_id": ELEVENLABS_MODEL,
        "voice_settings": {
            "stability": 0.5,
            "similarity_boost": 0.75,
        },
    }
    async with httpx.AsyncClient() as client:
        resp = await client.post(url, json=payload, headers=headers, timeout=30)
        resp.raise_for_status()
        return resp.content


def _kokoro_generate(text: str, voice: str = "af_heart") -> bytes:
    """Generate WAV audio via Kokoro-82M."""
    import io
    import soundfile as sf

    pipeline = _get_kokoro()
    chunks = []
    for _gs, _ps, audio in pipeline(text, voice=voice):
        chunks.append(audio)

    import numpy as np
    full_audio = np.concatenate(chunks)

    buf = io.BytesIO()
    sf.write(buf, full_audio, 24000, format="WAV")
    return buf.getvalue()


def _melo_generate(text: str, language: str = "EN") -> bytes:
    """Generate WAV audio via MeloTTS."""
    model, speaker_ids = _get_melo()

    speaker_key = f"{language}-Default"
    if speaker_key not in speaker_ids:
        speaker_key = list(speaker_ids.keys())[0]

    tmp = tempfile.NamedTemporaryFile(suffix=".wav", delete=False)
    tmp_path = tmp.name
    tmp.close()

    try:
        model.tts_to_file(text, speaker_ids[speaker_key], tmp_path)
        return Path(tmp_path).read_bytes()
    finally:
        Path(tmp_path).unlink(missing_ok=True)
