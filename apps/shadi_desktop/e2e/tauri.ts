import type { Page } from "@playwright/test";

/** What a mocked command answers: a value, or an error the panel shows. */
export type Answer = { ok: unknown } | { error: string };

export interface Call {
  cmd: string;
  args: Record<string, unknown>;
}

/**
 * Stand in for the Tauri backend: each `invoke(cmd)` gets `answers[cmd]`,
 * and anything unlisted fails the way an unavailable backend would. Every
 * call is recorded for {@link calls}.
 */
export async function mockTauri(page: Page, answers: Record<string, Answer>) {
  await page.addInitScript((answers: Record<string, Answer>) => {
    const w = window as unknown as Record<string, unknown> & { __shadiCalls: Call[] };
    w.__shadiCalls = [];
    let next = 1;
    w.__TAURI_INTERNALS__ = {
      invoke: async (cmd: string, args: Record<string, unknown>) => {
        w.__shadiCalls.push({ cmd, args: JSON.parse(JSON.stringify(args ?? {})) });
        const answer = answers[cmd];
        if (!answer) throw `no backend for ${cmd} in this test`;
        if ("error" in answer) throw answer.error;
        return answer.ok;
      },
      transformCallback: (callback: unknown) => {
        const id = next++;
        w[`_${id}`] = callback;
        return id;
      },
      unregisterCallback: () => {},
      convertFileSrc: (path: string) => path,
    };
    w.__TAURI_EVENT_PLUGIN_INTERNALS__ = { unregisterListener: () => {} };
  }, answers);
}

export async function calls(page: Page): Promise<Call[]> {
  return page.evaluate(() => (window as unknown as { __shadiCalls: Call[] }).__shadiCalls);
}
