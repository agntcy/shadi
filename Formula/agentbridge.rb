# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

class Agentbridge < Formula
  desc "CLI binary for the agentbridge general-purpose agent interconnect."
  homepage "https://github.com/agntcy/shadi"
  version "0.1.3"
  license "Apache-2.0"
  head "https://github.com/agntcy/shadi.git", branch: "main"

  on_macos do
    on_arm do
      url "https://github.com/agntcy/shadi/releases/download/agntcy-agentbridge-cli-v0.1.3/agentbridge-v0.1.3-aarch64-apple-darwin.tar.gz"
      sha256 "65d18f4582dfe7bd6fd6e776c209e979eb4a47e179503fade9aa16f3a9881b38"
    end

    on_intel do
      url "https://github.com/agntcy/shadi/releases/download/agntcy-agentbridge-cli-v0.1.3/agentbridge-v0.1.3-x86_64-apple-darwin.tar.gz"
      sha256 "77292b752a2f8a92f435baf28952cbffd3168dd36b03a55fcc0c5bdc7a8c6549"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/agntcy/shadi/releases/download/agntcy-agentbridge-cli-v0.1.3/agentbridge-v0.1.3-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "bfc5fa331bb7ec001d8467155f9ba14036177c507b229a9184967f41d22d3c29"
    end

    on_intel do
      url "https://github.com/agntcy/shadi/releases/download/agntcy-agentbridge-cli-v0.1.3/agentbridge-v0.1.3-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "bb1695e96f8a88255524c1a0d0698f9cb32b27a7fd9286291601b661466f7a9d"
    end
  end

  def install
    bin.install "agentbridge"
  end

  test do
    assert_match "agentbridge", shell_output("#{bin}/agentbridge --help")
  end
end
