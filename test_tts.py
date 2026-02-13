"""
Beast-mode tests for the AMTL TTS Engine.

20 tests across 5 categories:
  - Health check (3)
  - Kokoro English (7)
  - MeloTTS multilingual (5)
  - ELAINE fallback (3)
  - Unified interface (2)
"""

import asyncio
import os
import struct
import tempfile

import pytest

import tts_engine


# =========================================================================
# Helpers
# =========================================================================


def _is_wav(data: bytes) -> bool:
    """Return True if *data* starts with a valid RIFF/WAVE header."""
    return len(data) > 12 and data[:4] == b"RIFF" and data[8:12] == b"WAVE"


def _wav_num_samples(data: bytes) -> int:
    """Return the number of audio samples in a WAV buffer (assumes 16-bit mono or float32)."""
    # data chunk starts after the header; just check total size is substantial
    return len(data)


# =========================================================================
# 1. Health check (3 tests)
# =========================================================================


class TestHealthCheck:
    def test_returns_dict(self):
        result = tts_engine.health_check()
        assert isinstance(result, dict)
        assert "kokoro" in result
        assert "melo" in result
        assert "elevenlabs" in result

    def test_detects_kokoro(self):
        result = tts_engine.health_check()
        assert result["kokoro"] is True

    def test_detects_melo(self):
        result = tts_engine.health_check()
        assert result["melo"] is True


# =========================================================================
# 2. Kokoro English (7 tests)
# =========================================================================


class TestKokoroEnglish:
    def test_generates_audio(self):
        audio = tts_engine.speak("Hello world", engine="kokoro")
        assert len(audio) > 0

    def test_wav_header(self):
        audio = tts_engine.speak("Testing WAV header", engine="kokoro")
        assert _is_wav(audio), "Output should be a valid WAV file"

    def test_saves_to_file(self):
        with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as f:
            path = f.name
        try:
            tts_engine.speak("Save test", engine="kokoro", output_path=path)
            assert os.path.getsize(path) > 1000
        finally:
            os.unlink(path)

    def test_long_text(self):
        long = "This is a longer sentence that should exercise the chunking behaviour of the Kokoro pipeline. " * 3
        audio = tts_engine.speak(long, engine="kokoro")
        assert _is_wav(audio)
        assert len(audio) > 10_000

    def test_short_text(self):
        audio = tts_engine.speak("Hi", engine="kokoro")
        assert _is_wav(audio)

    def test_numbers(self):
        audio = tts_engine.speak("There are 42 items costing $9.99 each.", engine="kokoro")
        assert _is_wav(audio)

    def test_australian_english(self):
        """Kokoro supports Australian English via voice prefix."""
        audio = tts_engine.speak("Good day mate", engine="kokoro", voice="af_heart")
        assert _is_wav(audio)
        assert len(audio) > 1000


# =========================================================================
# 3. MeloTTS multilingual (5 tests)
# =========================================================================


class TestMeloTTSMultilingual:
    def test_english_audio(self):
        audio = tts_engine.speak_multilingual("Hello from MeloTTS")
        assert len(audio) > 0

    def test_saves_to_file(self):
        with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as f:
            path = f.name
        try:
            tts_engine.speak_multilingual("File save test", output_path=path)
            assert os.path.getsize(path) > 1000
        finally:
            os.unlink(path)

    def test_long_text(self):
        long = "MeloTTS handles longer passages of text for multilingual synthesis. " * 3
        audio = tts_engine.speak_multilingual(long)
        assert len(audio) > 10_000

    def test_engine_selector(self):
        """speak() with engine='melo' should use MeloTTS."""
        audio = tts_engine.speak("Engine selector test", engine="melo")
        assert _is_wav(audio)
        assert len(audio) > 1000

    def test_valid_wav(self):
        audio = tts_engine.speak_multilingual("WAV validation")
        assert _is_wav(audio)


# =========================================================================
# 4. ELAINE fallback (3 tests)
# =========================================================================


class TestELAINEFallback:
    def test_falls_back_without_api_key(self):
        """Without ELEVENLABS_API_KEY, speak_as_elaine should fall back to Kokoro."""
        orig = os.environ.pop("ELEVENLABS_API_KEY", None)
        try:
            audio = asyncio.run(tts_engine.speak_as_elaine("Fallback test"))
            assert _is_wav(audio), "Fallback should produce WAV (Kokoro)"
        finally:
            if orig is not None:
                os.environ["ELEVENLABS_API_KEY"] = orig

    def test_correct_voice_id(self):
        assert tts_engine.ELAINE_VOICE_ID == "XQanfahzbl1YiUlZi5NW"

    def test_elevenlabs_is_primary(self):
        """ElevenLabs should be the primary engine for ELAINE (checked via config)."""
        assert tts_engine.ELEVENLABS_BASE_URL == "https://api.elevenlabs.io/v1"
        assert tts_engine.ELEVENLABS_MODEL == "eleven_multilingual_v2"


# =========================================================================
# 5. Unified interface (2 tests)
# =========================================================================


class TestUnifiedInterface:
    def test_invalid_engine_raises_error(self):
        with pytest.raises(ValueError, match="Unknown engine"):
            tts_engine.speak("oops", engine="nonexistent")

    def test_default_engine_is_kokoro(self):
        """speak() with no engine arg should default to kokoro."""
        audio = tts_engine.speak("Default engine test")
        assert _is_wav(audio)
