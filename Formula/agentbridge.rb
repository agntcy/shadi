# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

class Agentbridge < Formula
  desc "CLI binary for the agentbridge general-purpose agent interconnect."
  homepage "https://github.com/agntcy/shadi"
  version "0.3.0"
  license "Apache-2.0"
  head "https://github.com/agntcy/shadi.git", branch: "main"

  on_macos do
    on_arm do
      url "https://github.com/agntcy/shadi/releases/download/agntcy-agentbridge-cli-v0.3.0/agentbridge-v0.3.0-aarch64-apple-darwin.tar.gz"
      sha256 "52437a7c557f45cb251a77427940c9ed2c4bf59a2ff7ad35e020a465b8175024"
    end

    on_intel do
      url "https://github.com/agntcy/shadi/releases/download/agntcy-agentbridge-cli-v0.3.0/agentbridge-v0.3.0-x86_64-apple-darwin.tar.gz"
      sha256 "a61f1a0db55a5a81352ed03b47e7e06de588b204b13fc465b739b1e2c778f582"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/agntcy/shadi/releases/download/agntcy-agentbridge-cli-v0.3.0/agentbridge-v0.3.0-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "c953dcc6bf9de892de1c251a37bf298805bc405fc4868ad753d054d4bc5cdd2c"
    end

    on_intel do
      url "https://github.com/agntcy/shadi/releases/download/agntcy-agentbridge-cli-v0.3.0/agentbridge-v0.3.0-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "4bc614ead5cb169aba75bbf1fdf4b2a0cc6d83dc15ac0561d3f0f953b1872d63"
    end
  end

  def install
    bin.install "agentbridge"
  end

  test do
    assert_match "agentbridge", shell_output("#{bin}/agentbridge --help")
  end
end
