import { expect, test } from "@playwright/test";
import { calls, mockTauri } from "./tauri";

const OWNER = "did:key:z6MkOwner";

test("every tab renders without crashing", async ({ page }) => {
  const crashes: string[] = [];
  page.on("pageerror", (err) => crashes.push(err.message));
  await mockTauri(page, { slim_group_list: { ok: [] } });
  await page.goto("/");
  for (const tab of ["Identity", "Keys", "Sandbox", "Policy", "Rooms", "Directory", "Owner", "agentbridge", "Traces"]) {
    await page.getByRole("button", { name: tab, exact: true }).click();
    await expect(page.locator("h2").first()).toBeVisible();
  }
  expect(crashes).toEqual([]);
});

test("the secret store is browsed by name and never read", async ({ page }) => {
  await mockTauri(page, {
    slim_group_list: { ok: [] },
    secret_backend_status: { ok: { kind: "keychain", platform: "macOS Keychain" } },
    secret_list_keychain: { ok: [{ key: "agent_keys/codex/did" }, { key: "agent_keys/codex/private" }] },
    secret_exists: { ok: true },
  });
  await page.goto("/");
  await page.getByRole("button", { name: "Keys", exact: true }).click();
  await expect(page.getByText("Backed by the macOS Keychain.")).toBeVisible();

  await page.getByPlaceholder("Prefix, e.g. agent_keys/").fill("agent_keys/");
  await page.getByRole("button", { name: "List keys" }).click();
  await expect(page.getByText("agent_keys/codex/private")).toBeVisible();

  await page.getByPlaceholder("Key name").fill("agent_keys/codex/private");
  await page.getByRole("button", { name: "Is it stored?" }).click();
  await expect(page.getByText("agent_keys/codex/private is stored")).toBeVisible();

  const made = (await calls(page)).map((c) => c.cmd);
  expect(made).toContain("secret_exists");
  expect(made).not.toContain("secret_get");
});

test("the owner sees an ask in the inbox and allows it", async ({ page }) => {
  await mockTauri(page, {
    slim_group_list: { ok: [] },
    owner_status: {
      ok: { running: true, owner_did: OWNER, service: "agntcy/shadi/avatar-owner", channels: ["agntcy/shadi/room"] },
    },
    owner_pending: {
      ok: [
        {
          id: 7,
          request: {
            channel: "agntcy/shadi/room",
            invitee_name: "agntcy/shadi/copilot",
            invitee_did: null,
            action: "add",
            requester: "did:key:z6MkCodex",
            requester_human_did: null,
          },
          asked_at: 0,
          expires_at: 4102444800,
        },
      ],
    },
    owner_policy_get: { ok: "{}\n" },
    owner_audit: { ok: [] },
    owner_approve: { ok: null },
  });
  await page.goto("/");
  await page.getByRole("button", { name: "Owner", exact: true }).click();
  await expect(page.getByRole("cell", { name: "agntcy/shadi/copilot" })).toBeVisible();
  await page.getByRole("button", { name: "Allow" }).click();
  await expect
    .poll(async () => (await calls(page)).find((c) => c.cmd === "owner_approve")?.args)
    .toEqual({ askId: 7 });
});

test("a directory search shows what it found", async ({ page }) => {
  await mockTauri(page, {
    slim_group_list: { ok: [] },
    dir_search: {
      ok: [{ cid: "bafy1", name: "copilot", did: "did:key:z6MkCopilot", skills: ["review"], record_json: "{}" }],
    },
  });
  await page.goto("/");
  await page.getByRole("button", { name: "Directory", exact: true }).click();
  await page.getByPlaceholder("DIR server, e.g. localhost:8888").fill("localhost:8888");
  await page.getByPlaceholder("Skill, or an agent's did:key").fill("review");
  await page.getByRole("button", { name: "Search" }).click();
  await expect(page.getByText("copilot", { exact: true })).toBeVisible();
  await expect(page.getByText("did:key:z6MkCopilot")).toBeVisible();
  // Nothing to invite into until a room is moderated here.
  await expect(page.getByRole("button", { name: "Invite" })).toBeDisabled();
  const search = (await calls(page)).find((c) => c.cmd === "dir_search");
  expect(search?.args).toEqual({ query: "review", dirServer: "localhost:8888", limit: 20 });
});
