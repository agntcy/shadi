/* Copyright SHADI Contributors */
/* SPDX-License-Identifier: Apache-2.0 */

/* Scripted demo lines and canned CLI responses for the home-page terminal. */
window.ShadictlDemoData = {
  demoTitles: {
    sandbox: "user@shadi:~",
    policy: "user@shadi:~",
  },

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
