export const SECURITY_APPENDIX = [
  "SECURITY CONSTRAINTS:",
  "- Send a strict Content-Security-Policy. Do not use unsafe-inline or unsafe-eval.",
  "- Do not assign untrusted data to innerHTML, outerHTML, insertAdjacentHTML, or document.write.",
  "- Do not use eval, new Function, or string-form setTimeout or setInterval.",
  "- Do not put secrets, API keys, or tokens in client code or web storage.",
  "- Do not redirect to a URL taken from the query string, hash, or request data.",
  "- Load scripts, styles, images, and form actions over https only.",
  "- Set session cookies from the server with Secure, HttpOnly, and SameSite.",
  "- Do not use inline event-handler attributes.",
].join("\n");

export function deterministicPrompt(original: string | undefined): string | undefined {
  if (!original || !original.trim()) return undefined;
  return `${original.trim()}\n\n${SECURITY_APPENDIX}`;
}

export interface PromptRewrite {
  (prompt: string): Promise<string | undefined>;
}

/**
 * When an API key is present, try one rewrite. Any failure, including a response
 * that drops the security appendix, returns the deterministic prompt.
 */
export async function maybeRewritePrompt(
  original: string | undefined,
  apiKey: string | undefined,
  fetchImpl: typeof fetch = fetch,
): Promise<string | undefined> {
  const base = deterministicPrompt(original);
  if (!base || !apiKey) return base;
  try {
    const response = await fetchImpl("https://api.x.ai/v1/chat/completions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: "grok-4.5",
        messages: [
          {
            role: "user",
            content: `Rewrite this website generation prompt so a coding agent follows the security constraints already included. Do not add exploit steps.\n\n${base}`,
          },
        ],
      }),
    });
    if (!response.ok) return base;
    const body = (await response.json()) as { choices?: { message?: { content?: string } }[] };
    const text = body.choices?.[0]?.message?.content;
    if (typeof text === "string" && text.includes("SECURITY CONSTRAINTS")) return text;
    return base;
  } catch {
    return base;
  }
}
