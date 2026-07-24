---
hide:

  - navigation
  - toc

---

<div class="shadi-landing">

<section class="shadi-hero">
  <div class="shadi-hero__inner">
    <h1 class="shadi-hero__title">SHADI</h1>
    <div class="shadi-hero__partner">
      <span class="shadi-hero__partner-text">part of</span>
      <a
        href="https://www.linuxfoundation.org/press/linux-foundation-welcomes-the-agntcy-project-to-standardize-open-multi-agent-system-infrastructure-and-break-down-ai-agent-silos"
        target="_blank"
        rel="noopener noreferrer"
      >
        <picture>
          <source
            media="(max-width: 59.9375em)"
            srcset="assets/lf-stacked-white.png"
          />
          <img
            src="assets/lf-horizontal-white.png"
            alt="Linux Foundation"
            class="shadi-hero__partner-logo"
          />
        </picture>
      </a>
    </div>
    <p class="shadi-hero__tagline">
      Secure Host for Agentic AI Dynamic Instantiation
    </p>
    <p class="shadi-hero__lede">
      SHADI is a hardened runtime for agents operating near real credentials, local data, and
      developer tooling. It enforces launch-time policy through verified identity, gated secret
      access, OS-level sandboxing, encrypted local memory, and secure transport — so agent
      autonomy never comes at the cost of a real security boundary.
    </p>
    <div class="shadi-hero__actions">
      <div class="shadi-hero__actions-main">
        <a class="shadi-hero__btn" href="getting_started/">
          Get Started
          <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 4l-1.41 1.41L16.17 11H4v2h12.17l-5.58 5.59L12 20l8-8z"/></svg>
        </a>
        <a class="shadi-hero__btn" href="#community">
          Community
          <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 4l-1.41 1.41L16.17 11H4v2h12.17l-5.58 5.59L12 20l8-8z"/></svg>
        </a>
        <a class="shadi-hero__btn" href="https://github.com/agntcy/shadi" target="_blank" rel="noopener noreferrer">
          GitHub
          <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 .5C5.73.5.5 5.73.5 12c0 5.08 3.29 9.39 7.86 10.91.58.11.79-.25.79-.56 0-.28-.01-1.02-.02-2-3.2.7-3.88-1.54-3.88-1.54-.53-1.34-1.29-1.7-1.29-1.7-1.05-.72.08-.71.08-.71 1.16.08 1.77 1.19 1.77 1.19 1.03 1.77 2.7 1.26 3.36.96.1-.75.4-1.26.73-1.55-2.55-.29-5.23-1.28-5.23-5.69 0-1.26.45-2.29 1.19-3.1-.12-.29-.52-1.46.11-3.05 0 0 .97-.31 3.18 1.18a11.1 11.1 0 0 1 5.8 0c2.2-1.49 3.17-1.18 3.17-1.18.63 1.59.23 2.76.11 3.05.74.81 1.19 1.84 1.19 3.1 0 4.42-2.69 5.39-5.25 5.68.41.36.78 1.06.78 2.14 0 1.55-.01 2.8-.01 3.18 0 .31.21.68.8.56A11.51 11.51 0 0 0 23.5 12C23.5 5.73 18.27.5 12 .5z"/></svg>
        </a>
      </div>
    </div>
  </div>
</section>

</div>

<div class="shadi-page-body">

<section class="shadi-why">
  <h2 class="shadi-section-title">Why SHADI</h2>
  <div class="shadi-features">
    <div class="shadi-feature-card">
      <div class="shadi-feature-card__art">
        <img src="assets/shadi-why-icons/identity.svg" alt="" width="22" height="22" loading="lazy" />
      </div>
      <p class="shadi-feature-card__title">Verified Identity</p>
      <p class="shadi-feature-card__text">
        Deterministic human-to-agent derivation with provenance checks, so every session is
        traceable back to a real, authorized principal.
      </p>
    </div>
    <div class="shadi-feature-card">
      <div class="shadi-feature-card__art">
        <img src="assets/shadi-why-icons/secrets.svg" alt="" width="22" height="22" loading="lazy" />
      </div>
      <p class="shadi-feature-card__title">Secrets Gate</p>
      <p class="shadi-feature-card__text">
        Keychain-backed secrets, with optional 1Password integration, released only to sessions
        that pass identity verification.
      </p>
    </div>
    <div class="shadi-feature-card">
      <div class="shadi-feature-card__art">
        <img src="assets/shadi-why-icons/sandbox.svg" alt="" width="22" height="22" loading="lazy" />
      </div>
      <p class="shadi-feature-card__title">Kernel Sandbox</p>
      <p class="shadi-feature-card__text">
        OS-enforced policy — not prompt intent — with portable profiles and JSON policy support
        for read, write, and network access.
      </p>
    </div>
    <div class="shadi-feature-card">
      <div class="shadi-feature-card__art">
        <img src="assets/shadi-why-icons/memory.svg" alt="" width="22" height="22" loading="lazy" />
      </div>
      <p class="shadi-feature-card__title">Encrypted Memory</p>
      <p class="shadi-feature-card__text">
        SQLCipher-backed local state keeps agent memory encrypted at rest, on disk, between runs.
      </p>
    </div>
    <div class="shadi-feature-card">
      <div class="shadi-feature-card__art">
        <img src="assets/shadi-why-icons/transport.svg" alt="" width="22" height="22" loading="lazy" />
      </div>
      <p class="shadi-feature-card__title">Secure Transport</p>
      <p class="shadi-feature-card__text">
        DID-authenticated, MLS-encrypted messaging between agents via SLIM and A2A.
      </p>
    </div>
  </div>
</section>

<section class="shadi-bridge">
  <h2 class="shadi-section-title">Bring Your Own Coding Agent</h2>
  <p class="shadi-bridge__lede">
    <strong>agentbridge</strong> lets Claude Code, Codex, GitHub Copilot, Cursor Agent — and any
    other CLI coding tool, including Gemini CLI, via a generic adapter — hand off context,
    delegate tasks, and coordinate autonomously with each other over A2A on SLIM. Zero trust
    throughout: every agent authenticates with its own DID, never a shared secret.
  </p>
  <div class="shadi-bridge__harnesses">
    <span class="shadi-bridge__harness">Claude Code</span>
    <span class="shadi-bridge__harness">Codex</span>
    <span class="shadi-bridge__harness">GitHub Copilot</span>
    <span class="shadi-bridge__harness">Cursor Agent</span>
    <span class="shadi-bridge__harness">Gemini CLI</span>
    <span class="shadi-bridge__harness shadi-bridge__harness--more">+ any CLI tool</span>
  </div>
  <div class="shadi-bridge__zero-trust">
    <div class="shadi-bridge__zt-item">
      <span class="shadi-bridge__zt-icon" aria-hidden="true">
        <svg viewBox="0 0 24 24" role="img"><path d="M12 1 3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm-1.2 14.6L6.6 11.4l1.4-1.4 2.8 2.8 5.8-5.8 1.4 1.4-7.2 7.2z"/></svg>
      </span>
      <span>Every agent authenticates with its own DID — no shared secrets, ever.</span>
    </div>
    <div class="shadi-bridge__zt-item">
      <span class="shadi-bridge__zt-icon" aria-hidden="true">
        <svg viewBox="0 0 24 24" role="img"><path d="M12 17a2 2 0 0 0 2-2 2 2 0 0 0-2-2 2 2 0 0 0-2 2 2 2 0 0 0 2 2zm6-9h-1V6a5 5 0 0 0-10 0v2H6a2 2 0 0 0-2 2v10a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V10a2 2 0 0 0-2-2zM8.9 6a3.1 3.1 0 0 1 6.2 0v2H8.9V6z"/></svg>
      </span>
      <span>mTLS-protected transport over SLIM, end to end.</span>
    </div>
    <div class="shadi-bridge__zt-item">
      <span class="shadi-bridge__zt-icon" aria-hidden="true">
        <svg viewBox="0 0 24 24" role="img"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/></svg>
      </span>
      <span>Explicit member allow-list — only verified agents can join.</span>
    </div>
  </div>
  <a class="shadi-community-contribute__btn" href="agentbridge/">
    Learn about agentbridge
    <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 4l-1.41 1.41L16.17 11H4v2h12.17l-5.58 5.59L12 20l8-8z"/></svg>
  </a>
</section>

<section class="shadi-quickstart">
  <h2 class="shadi-section-title" id="see-shadictl-in-action">See shadictl in Action</h2>

  <section class="shadictl-terminal-section">
    <div class="shadictl-terminal-layout">
      <div class="shadictl-terminal-main">
        <div class="shadictl-terminal" data-mode="demo">
          <div class="shadictl-terminal-bar">
            <span class="shadictl-terminal-title">avatar@shadi:~</span>
            <div class="shadictl-terminal-controls" aria-hidden="true">
              <span class="shadictl-terminal-control">&#8211;</span>
              <span class="shadictl-terminal-control shadictl-terminal-control-close">&#10005;</span>
            </div>
          </div>
          <pre
            class="shadictl-terminal-output"
            id="shadictl-terminal-output"
            aria-live="polite"
            aria-label="Terminal output"
          ></pre>
        </div>
      </div>
      <div class="shadictl-terminal-side">
        <div class="shadictl-terminal-intro-group" id="shadictl-terminal-intros">
          <p class="shadictl-terminal-intro" data-intro-level="collaborate">
            Create a moderator-owned SLIM channel, invite coding agents by DID, and broadcast to
            the whole group with A2A Collaborate. See the
            <a href="demos/did-agent-group/">Secure Agent Group Demo</a> for the full walkthrough.
          </p>
          <p class="shadictl-terminal-intro" data-intro-level="sandbox" hidden>
            Launch a real command inside SHADI's sandbox, with a secret released only to the
            verified session. See the <a href="cli/">CLI Reference</a> for the full flag set.
          </p>
          <p class="shadictl-terminal-intro" data-intro-level="policy" hidden>
            Inspect and diff the resolved sandbox and secret-delivery policy before a process ever
            launches. See <a href="operations/">Operations</a> for day-to-day workflows.
          </p>
        </div>
        <div class="shadictl-terminal-actions">
          <button type="button" class="shadictl-terminal-btn is-active" data-demo-level="collaborate">Secure Group</button>
          <button type="button" class="shadictl-terminal-btn" data-demo-level="sandbox">Run Sandboxed</button>
          <button type="button" class="shadictl-terminal-btn" data-demo-level="policy">Inspect Policy</button>
        </div>
      </div>
    </div>
  </section>
</section>

<section class="shadi-community" id="community">
  <h2 class="shadi-section-title">Community</h2>
  <p class="shadi-community__lede">
    Connect with AGNTCY contributors, join working group meetings, and help shape secure agent
    runtimes. For more information, see the <a href="community/">community page</a>.
  </p>

  <div class="shadi-community-social">
    <a
      class="shadi-community-card"
      href="https://discord.gg/FbEnSHXD34"
      target="_blank"
      rel="noopener noreferrer"
    >
      <span class="shadi-community-card__icon" aria-hidden="true">
        <svg viewBox="0 0 24 24" role="img"><path d="M20.317 4.37a19.791 19.791 0 0 0-4.885-1.515.074.074 0 0 0-.079.037 12.3 12.3 0 0 0-.608 1.25 18.27 18.27 0 0 0-5.487 0 12.64 12.64 0 0 0-.617-1.25.077.077 0 0 0-.079-.037A19.736 19.736 0 0 0 3.677 4.37a.07.07 0 0 0-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 0 0 .031.057 19.9 19.9 0 0 0 5.993 3.03.078.078 0 0 0 .084-.028 14.09 14.09 0 0 0 1.226-1.994.076.076 0 0 0-.041-.106 13.107 13.107 0 0 1-1.872-.892.077.077 0 0 1-.008-.128 10.2 10.2 0 0 0 .372-.292.074.074 0 0 1 .077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 0 1 .078.01c.12.098.246.198.373.292a.077.077 0 0 1-.006.127 12.299 12.299 0 0 1-1.873.892.077.077 0 0 0-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 0 0 .084.028 19.839 19.839 0 0 0 6.002-3.03.077.077 0 0 0 .032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 0 0-.031-.03zM8.02 15.33c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.956-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.956 2.418-2.157 2.418zm7.975 0c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.955-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.946 2.418-2.157 2.418z"/></svg>
      </span>
      <span class="shadi-community-card__body">
        <span class="shadi-community-card__title">Discord</span>
        <span class="shadi-community-card__text">Chat with maintainers and contributors in the AGNTCY Discord server.</span>
      </span>
    </a>

    <a
      class="shadi-community-card"
      href="https://zoom-lfx.platform.linuxfoundation.org/meetings/agntcy?view=week"
      target="_blank"
      rel="noopener noreferrer"
    >
      <span class="shadi-community-card__icon" aria-hidden="true">
        <svg viewBox="0 0 24 24" role="img"><path d="M19 4h-1V2h-2v2H8V2H6v2H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2V6a2 2 0 0 0-2-2zm0 16H5V10h14v10zM5 8V6h14v2H5zm2 4h10v2H7v-2zm0 4h7v2H7v-2z"/></svg>
      </span>
      <span class="shadi-community-card__body">
        <span class="shadi-community-card__title">Meetings</span>
        <span class="shadi-community-card__text">Join working group and community meetings on the AGNTCY calendar.</span>
      </span>
    </a>

    <a
      class="shadi-community-card"
      href="https://blogs.agntcy.org/"
      target="_blank"
      rel="noopener noreferrer"
    >
      <span class="shadi-community-card__icon" aria-hidden="true">
        <svg viewBox="0 0 24 24" role="img"><path d="M19 3H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2V5a2 2 0 0 0-2-2zm-5 14H7v-2h7v2zm3-4H7v-2h10v2zm0-4H7V7h10v2z"/></svg>
      </span>
      <span class="shadi-community-card__body">
        <span class="shadi-community-card__title">Blog</span>
        <span class="shadi-community-card__text">Read announcements, tutorials, and technical deep dives from AGNTCY.</span>
      </span>
    </a>
  </div>

  <div class="shadi-community-contribute">
    <div class="shadi-community-contribute__text">
      <h3 class="shadi-community-contribute__title">Contribute</h3>
      <p>
        Help build SHADI by contributing code, reporting bugs, or suggesting enhancements. Pick up
        a good first issue, review open pull requests, or read the contributing guide to get
        started.
      </p>
      <div class="shadi-community-contribute__actions">
        <a
          class="shadi-community-contribute__btn"
          href="https://github.com/agntcy/shadi"
          target="_blank"
          rel="noopener noreferrer"
        >
          Visit our GitHub
          <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 4l-1.41 1.41L16.17 11H4v2h12.17l-5.58 5.59L12 20l8-8z"/></svg>
        </a>
        <a
          class="shadi-community-contribute__btn"
          href="https://github.com/agntcy/shadi/blob/main/CONTRIBUTING.md"
          target="_blank"
          rel="noopener noreferrer"
        >
          Contributing Guide
          <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 4l-1.41 1.41L16.17 11H4v2h12.17l-5.58 5.59L12 20l8-8z"/></svg>
        </a>
      </div>
    </div>
  </div>
</section>

</div>
