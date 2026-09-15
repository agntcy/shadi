# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

class Agentbridge < Formula
  desc "CLI binary for the agentbridge general-purpose agent interconnect."
  homepage "https://github.com/agntcy/shadi"
  version "0.1.7"
  license "Apache-2.0"
  head "https://github.com/agntcy/shadi.git", branch: "main"

  on_macos do
    on_arm do
      url "https://github.com/agntcy/shadi/releases/download/agntcy-agentbridge-cli-v0.1.7/agentbridge-v0.1.7-aarch64-apple-darwin.tar.gz"
      sha256 "4cd38dd38bb758a7f2e4eea59f616e40221aeb7aa742cd4009624329a12c7fd9"
    end

    on_intel do
      url "https://github.com/agntcy/shadi/releases/download/agntcy-agentbridge-cli-v0.1.7/agentbridge-v0.1.7-x86_64-apple-darwin.tar.gz"
      sha256 "0e61ce0726fd662eeb0a5166903c63cd2fcc4e350690966921abfc846d137c8f"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/agntcy/shadi/releases/download/agntcy-agentbridge-cli-v0.1.7/agentbridge-v0.1.7-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "dce31f76e9c0471f297c3b1cd72576ca1244c16b25f9854c4bca3e365a8d834e"
    end

    on_intel do
      url "https://github.com/agntcy/shadi/releases/download/agntcy-agentbridge-cli-v0.1.7/agentbridge-v0.1.7-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "daff90f22e69555b46100b7798b55c854ac066cfa8501bb4f8163ecf1e6296af"
    end
  end

  def install
    bin.install "agentbridge"
  end

  test do
    assert_match "agentbridge", shell_output("#{bin}/agentbridge --help")
  end
end
