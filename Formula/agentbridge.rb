# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

class Agentbridge < Formula
  desc "CLI binary for the agentbridge general-purpose agent interconnect."
  homepage "https://github.com/agntcy/shadi"
  version "0.2.0"
  license "Apache-2.0"
  head "https://github.com/agntcy/shadi.git", branch: "main"

  on_macos do
    on_arm do
      url "https://github.com/agntcy/shadi/releases/download/agntcy-agentbridge-cli-v0.2.0/agentbridge-v0.2.0-aarch64-apple-darwin.tar.gz"
      sha256 "ea868307d577622ab7154c0b024de8893cadfd830da387cb6ca090d82d7badae"
    end

    on_intel do
      url "https://github.com/agntcy/shadi/releases/download/agntcy-agentbridge-cli-v0.2.0/agentbridge-v0.2.0-x86_64-apple-darwin.tar.gz"
      sha256 "a11d7aa2ac0252a4b08cff897b0b5b875644538668cf9bd4636da30041740121"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/agntcy/shadi/releases/download/agntcy-agentbridge-cli-v0.2.0/agentbridge-v0.2.0-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "79e0dafd2b6f65ca1a085ba2bbe4da244d740fd1f0f1e726dde20659b7dac613"
    end

    on_intel do
      url "https://github.com/agntcy/shadi/releases/download/agntcy-agentbridge-cli-v0.2.0/agentbridge-v0.2.0-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "5838105a5982eaea8a5437f85349561040c30f7460c1e15b818776a0c9298c2c"
    end
  end

  def install
    bin.install "agentbridge"
  end

  test do
    assert_match "agentbridge", shell_output("#{bin}/agentbridge --help")
  end
end
