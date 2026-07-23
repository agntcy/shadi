/* Copyright SHADI Contributors */
/* SPDX-License-Identifier: Apache-2.0 */

/* Scripted demo lines and canned CLI responses for the home-page terminal. */
window.ShadictlDemoData = {
  demoTitles: {
    collaborate: "avatar@shadi:~",
    sandbox: "user@shadi:~",
    policy: "user@shadi:~",
  },

  collaborateDemoScript: [
    { type: "command", text: "shadictl shell" },
    { type: "pause", ms: 400 },
    { type: "shell", text: "/slim create agntcy/shadi/dev-room" },
    {
      type: "output",
      text:
        "created channel agntcy/shadi/dev-room as moderator agntcy/shadi/avatar\n" +
        "  (did:key:z6Mkix7t…) — human did:key:z6MkhVT…",
    },
    { type: "pause", ms: 1400 },
    { type: "shell", text: "/slim invite agntcy/shadi/claude-code" },
    { type: "output", text: "invited agntcy/shadi/claude-code to agntcy/shadi/dev-room" },
    { type: "shell", text: "/slim invite agntcy/shadi/codex" },
    { type: "output", text: "invited agntcy/shadi/codex to agntcy/shadi/dev-room" },
    { type: "pause", ms: 1400 },
    {
      type: "shell",
      text: '/slim a2a-collaborate claude-code,codex --message "status check" --timeout 15',
    },
    {
      type: "output",
      text:
        'broadcast "status check" to 2 peer(s); received:\n' +
        "  All systems normal\n" +
        "  Ready to collaborate",
    },
    { type: "pause", ms: 4000 },
  ],

  sandboxDemoScript: [
    {
      type: "command",
      text: "shadictl --profile balanced --inject-keychain GITHUB_TOKEN=GH_TOKEN -- git push",
    },
    {
      type: "output",
      text:
        'INFO shadictl: resolved profile "balanced" (sandbox: on, network: allowed)\n' +
        'INFO shadictl: secret "GITHUB_TOKEN" released to verified session\n' +
        "INFO shadictl: launching `git push` inside sandbox\n" +
        "Everything up-to-date",
    },
    { type: "pause", ms: 2200 },
    { type: "command", text: "shadictl --list-keychain --list-prefix GITHUB" },
    { type: "output", text: "GITHUB_TOKEN\nGITHUB_APP_ID" },
    { type: "pause", ms: 4000 },
  ],

  policyDemoScript: [
    { type: "command", text: "shadictl policy explain --format json" },
    {
      type: "output",
      text:
        "{\n" +
        '  "profile": "balanced",\n' +
        '  "sandbox": { "read": ["."], "write": ["."], "net": "allowed" },\n' +
        '  "secrets": { "backend": "keychain", "delivery": "process_inject_keychain" }\n' +
        "}",
    },
    { type: "pause", ms: 2200 },
    { type: "command", text: "shadictl policy diff --against profile:strict --format text" },
    {
      type: "output",
      text: "+ net-block: enabled\n+ allow-command: none\n- allow: .",
    },
    { type: "pause", ms: 4000 },
  ],
};
