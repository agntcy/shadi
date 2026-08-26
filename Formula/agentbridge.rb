# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

class Agentbridge < Formula
  desc "CLI binary for the agentbridge general-purpose agent interconnect."
  homepage "https://github.com/agntcy/shadi"
  version "0.1.4"
  license "Apache-2.0"
  head "https://github.com/agntcy/shadi.git", branch: "main"

  on_macos do
    on_arm do
      url "https://github.com/agntcy/shadi/releases/download/agntcy-agentbridge-cli-v0.1.4/agentbridge-v0.1.4-aarch64-apple-darwin.tar.gz"
      sha256 "e49760ff40bd3d4020c43210a648d9b398e11813c368f581d759429332177ffd"
    end

    on_intel do
      url "https://github.com/agntcy/shadi/releases/download/agntcy-agentbridge-cli-v0.1.4/agentbridge-v0.1.4-x86_64-apple-darwin.tar.gz"
      sha256 "7b049c2f2a648eed163c298e53eaa5b32db91adcb4f2f88b645655e97bdafe50"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/agntcy/shadi/releases/download/agntcy-agentbridge-cli-v0.1.4/agentbridge-v0.1.4-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "a250b1ba87fe3ae89ca5488cf805ac9a76c1802dd073cac1322194ad59aa84f6"
    end

    on_intel do
      url "https://github.com/agntcy/shadi/releases/download/agntcy-agentbridge-cli-v0.1.4/agentbridge-v0.1.4-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "7f02737910690ecd1e3227484b5eb65f151ab18e2d44a14ff36318d4b0cbcbf8"
    end
  end

  def install
    bin.install "agentbridge"
  end

  test do
    assert_match "agentbridge", shell_output("#{bin}/agentbridge --help")
  end
end
