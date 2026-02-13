# AMTL TTS Engine

Unified text-to-speech wrapper for Almost Magic Tech Lab.

**ELAINE's ElevenLabs voice (`XQanfahzbl1YiUlZi5NW`) is her PRIMARY voice.** These local models are for non-ELAINE TTS and local fallback only.

## Engines

| Engine | Use case | Requires |
|--------|----------|----------|
| **ElevenLabs** | ELAINE's primary voice | `ELEVENLABS_API_KEY` env var |
| **Kokoro-82M** | Local English TTS / ELAINE fallback | `pip install kokoro soundfile` |
| **MeloTTS** | Multilingual TTS | `pip install melotts` |

## Installation

```bash
pip install kokoro soundfile --break-system-packages
pip install melotts --break-system-packages
```

## Usage

```python
import asyncio
from tts_engine import speak, speak_as_elaine, speak_multilingual, health_check

# ELAINE (ElevenLabs primary, Kokoro fallback)
audio = asyncio.run(speak_as_elaine("Hello from ELAINE"))

# Local English TTS (Kokoro)
audio = speak("Hello world")

# Multilingual TTS (MeloTTS)
audio = speak_multilingual("Hello world", language="EN")

# Check which engines are available
status = health_check()
# {'kokoro': True, 'melo': True, 'elevenlabs': False}
```

## API

### `speak_as_elaine(text, output_path=None)` (async)
Speaks as ELAINE using ElevenLabs API. Falls back to Kokoro if `ELEVENLABS_API_KEY` is not set.

### `speak(text, engine="kokoro", voice="af_heart", output_path=None)`
Local English TTS. Supports `engine="kokoro"` (default) or `engine="melo"`.

### `speak_multilingual(text, language="EN", output_path=None)`
Multilingual TTS via MeloTTS.

### `health_check()`
Returns a dict of engine availability: `{"kokoro": bool, "melo": bool, "elevenlabs": bool}`.

## ELAINE Configuration

- **Voice ID**: `XQanfahzbl1YiUlZi5NW`
- **Model**: `eleven_multilingual_v2`
- **Base URL**: `https://api.elevenlabs.io/v1`

## Tests

```bash
python3 -m pytest test_tts.py -v
```

20 tests across 5 categories: health check, Kokoro English, MeloTTS multilingual, ELAINE fallback, and unified interface.
