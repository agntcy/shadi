# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

class Agentbridge < Formula
  desc "CLI binary for the agentbridge general-purpose agent interconnect."
  homepage "https://github.com/agntcy/shadi"
  version "0.1.6"
  license "Apache-2.0"
  head "https://github.com/agntcy/shadi.git", branch: "main"

  on_macos do
    on_arm do
      url "https://github.com/agntcy/shadi/releases/download/agntcy-agentbridge-cli-v0.1.6/agentbridge-v0.1.6-aarch64-apple-darwin.tar.gz"
      sha256 "4024862e296b5a3f011f2e5f5edc3faaf8331ebac42395e731f30bf3eebef71e"
    end

    on_intel do
      url "https://github.com/agntcy/shadi/releases/download/agntcy-agentbridge-cli-v0.1.6/agentbridge-v0.1.6-x86_64-apple-darwin.tar.gz"
      sha256 "06beb4448b934ae0818a6c6b4ebffb30651bb0ce4ab3cb6bab2d28fc7864eb43"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/agntcy/shadi/releases/download/agntcy-agentbridge-cli-v0.1.6/agentbridge-v0.1.6-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "1db7b7d2683135e8e64f330d25d025772df51f31aa4c5b494d045e6c8c0dc988"
    end

    on_intel do
      url "https://github.com/agntcy/shadi/releases/download/agntcy-agentbridge-cli-v0.1.6/agentbridge-v0.1.6-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "4cc0a7156c941b193a61e85526620286538eded65f58231ffcc3ee72e380dd93"
    end
  end

  def install
    bin.install "agentbridge"
  end

  test do
    assert_match "agentbridge", shell_output("#{bin}/agentbridge --help")
  end
end
