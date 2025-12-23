from __future__ import annotations

from typing import Dict, Any, Optional
import asyncio
import httpx


class LLMError(Exception):
    pass


def _clean_provider(p: Optional[str]) -> str:
    return (p or "").strip().lower()


async def _post_json_with_retries(
    url: str,
    *,
    headers: Dict[str, str] | None = None,
    params: Dict[str, str] | None = None,
    json: Dict[str, Any],
    timeout_s: int = 30,
    retries: int = 2,
) -> Dict[str, Any]:
    timeout = httpx.Timeout(timeout_s, connect=10.0, read=timeout_s, write=10.0, pool=10.0)
    limits = httpx.Limits(max_keepalive_connections=10, max_connections=20)

    last_err: Exception | None = None
    for attempt in range(retries + 1):
        try:
            async with httpx.AsyncClient(timeout=timeout, limits=limits) as client:
                r = await client.post(url, headers=headers, params=params, json=json)

                if r.status_code >= 400:
                    hint = ""
                    if r.status_code == 404 and "models/" in r.text:
                        hint = (
                            "\nHint: Model id not found. Use a current model like "
                            "`gemini-2.5-flash` and/or call the Models endpoint to list available models."
                        )
                    raise LLMError(f"HTTP {r.status_code}: {r.text}{hint}")

                return r.json()

        except (httpx.TimeoutException, httpx.NetworkError, LLMError) as e:
            last_err = e
            if attempt >= retries:
                break
            await asyncio.sleep(0.6 * (attempt + 1))

    raise LLMError(f"Request failed after retries: {last_err}")


async def call_openai_chat(
    api_key: str,
    model: str,
    system: str,
    user: str,
    temperature: float = 0.2,
    timeout_s: int = 30,
) -> str:
    if not api_key:
        raise LLMError("OpenAI API key missing")

    url = "https://api.openai.com/v1/chat/completions"
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    payload = {
        "model": model,
        "temperature": temperature,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    }

    data = await _post_json_with_retries(
        url,
        headers=headers,
        json=payload,
        timeout_s=timeout_s,
        retries=2,
    )

    try:
        return data["choices"][0]["message"]["content"].strip()
    except Exception:
        raise LLMError(f"OpenAI malformed response: {data}")


async def call_gemini_generate(
    api_key: str,
    model: str,
    system: str,
    user: str,
    temperature: float = 0.2,
    timeout_s: int = 30,
) -> str:
    if not api_key:
        raise LLMError("Gemini API key missing")

    model = (model or "").strip() or "gemini-2.5-flash"

    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"

    headers = {
        "Content-Type": "application/json",
        "x-goog-api-key": api_key,
    }

    prompt_text = f"{system.strip()}\n\n{user.strip()}"
    payload = {
        "contents": [{"role": "user", "parts": [{"text": prompt_text}]}],
        "generationConfig": {"temperature": temperature},
    }

    data = await _post_json_with_retries(
        url,
        headers=headers,
        json=payload,
        timeout_s=timeout_s,
        retries=2,
    )

    try:
        candidates = data.get("candidates") or []
        if not candidates:
            raise KeyError("No candidates")

        content = candidates[0].get("content") or {}
        parts = content.get("parts") or []
        if not parts:
            raise KeyError("No parts")

        text = parts[0].get("text")
        if not text:
            raise KeyError("No text")

        return str(text).strip()
    except Exception:
        raise LLMError(f"Gemini malformed response: {data}")


async def llm_generate(provider: str, cfg: Dict[str, Any], system: str, user: str) -> str:
    provider = _clean_provider(provider)

    if provider == "openai":
        return await call_openai_chat(
            api_key=str(cfg.get("openai_api_key", "")).strip(),
            model=str(cfg.get("openai_model", "gpt-4o-mini")).strip(),
            system=system,
            user=user,
        )

    if provider == "gemini":
        return await call_gemini_generate(
            api_key=str(cfg.get("gemini_api_key", "")).strip(),
            model=str(cfg.get("gemini_model", "gemini-2.5-flash")).strip(),
            system=system,
            user=user,
        )

    raise LLMError(f"Unsupported provider: {provider}")
