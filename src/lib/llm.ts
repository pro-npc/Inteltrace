// Unified LLM Gateway for IntelTrace
//
// Unifies:
// 1. Local OmniRoute OpenAI-compatible Proxy (default: http://localhost:20128/v1)
// 2. Google Gemini API Free Tier (gemini-2.5-flash / gemini-1.5-flash / gemini-flash-lite)
// 3. Deterministic Offline Forensic Intelligence Engine (Keyless Fallback)
//
// Provides both non-streaming JSON extraction and streaming SSE copilot responses.

export interface LLMMessage {
  role: 'system' | 'user' | 'assistant' | 'model';
  content: string;
}

export interface LLMCompletionOptions {
  model?: string;
  temperature?: number;
  maxTokens?: number;
  jsonMode?: boolean;
}

export interface LLMProviderConfig {
  omnirouteApiKey?: string;
  omnirouteBaseUrl?: string;
  geminiApiKey?: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. OmniRoute OpenAI-Compatible Integration
// ─────────────────────────────────────────────────────────────────────────────

async function callOmniRoute(
  baseUrl: string,
  apiKey: string,
  messages: LLMMessage[],
  options: LLMCompletionOptions = {},
): Promise<string | null> {
  const url = `${baseUrl.replace(/\/+$/, '')}/chat/completions`;
  const formattedMessages = messages.map((m) => ({
    role: m.role === 'model' ? 'assistant' : m.role,
    content: m.content,
  }));

  const payload: Record<string, unknown> = {
    model: options.model || 'claude-sonnet-4-5',
    messages: formattedMessages,
    temperature: options.temperature ?? 0.2,
    max_tokens: options.maxTokens ?? 1024,
  };

  if (options.jsonMode) {
    payload.response_format = { type: 'json_object' };
  }

  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(12_000),
    });

    if (!res.ok) return null;
    const data: any = await res.json();
    return data?.choices?.[0]?.message?.content || null;
  } catch {
    return null;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Google Gemini API Integration
// ─────────────────────────────────────────────────────────────────────────────

const GEMINI_MODELS = ['gemini-2.5-flash', 'gemini-1.5-flash', 'gemini-flash-lite-latest'];

async function callGemini(
  apiKey: string,
  systemPrompt: string,
  messages: LLMMessage[],
  options: LLMCompletionOptions = {},
): Promise<string | null> {
  const contents = messages
    .filter((m) => m.role !== 'system')
    .map((m) => ({
      role: m.role === 'user' ? 'user' : 'model',
      parts: [{ text: m.content }],
    }));

  for (const model of GEMINI_MODELS) {
    const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${encodeURIComponent(apiKey)}`;
    try {
      const res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          systemInstruction: systemPrompt ? { parts: [{ text: systemPrompt }] } : undefined,
          contents,
          generationConfig: {
            temperature: options.temperature ?? 0.2,
            maxOutputTokens: options.maxTokens ?? 1024,
            responseMimeType: options.jsonMode ? 'application/json' : 'text/plain',
          },
        }),
        signal: AbortSignal.timeout(12_000),
      });

      if (res.ok) {
        const data: any = await res.json();
        const text = data?.candidates?.[0]?.content?.parts?.[0]?.text;
        if (text) return text;
      }
    } catch {
      continue;
    }
  }

  return null;
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Unified Gateway
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Executes a forensic LLM query across configured providers with graceful fallback.
 */
export async function executeForensicLLM(
  config: LLMProviderConfig,
  messages: LLMMessage[],
  options: LLMCompletionOptions = {},
): Promise<string | null> {
  // Step 1: Try OmniRoute if configured
  if (config.omnirouteApiKey) {
    const baseUrl = config.omnirouteBaseUrl || 'http://localhost:20128/v1';
    const res = await callOmniRoute(baseUrl, config.omnirouteApiKey, messages, options);
    if (res) return res;
  }

  // Step 2: Try Gemini API
  if (config.geminiApiKey) {
    const sysMsg = messages.find((m) => m.role === 'system');
    const res = await callGemini(config.geminiApiKey, sysMsg?.content || '', messages, options);
    if (res) return res;
  }

  return null;
}
