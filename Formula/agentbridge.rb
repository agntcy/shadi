# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

class Agentbridge < Formula
  desc "CLI binary for the agentbridge general-purpose agent interconnect."
  homepage "https://github.com/agntcy/shadi"
  version "0.1.8"
  license "Apache-2.0"
  head "https://github.com/agntcy/shadi.git", branch: "main"

  on_macos do
    on_arm do
      url "https://github.com/agntcy/shadi/releases/download/agntcy-agentbridge-cli-v0.1.8/agentbridge-v0.1.8-aarch64-apple-darwin.tar.gz"
      sha256 "3b6dad9424bb4a2ee8d061d9fd43ff75cb9076fb50d8ef6b4bb92846c8da4ac8"
    end

    on_intel do
      url "https://github.com/agntcy/shadi/releases/download/agntcy-agentbridge-cli-v0.1.8/agentbridge-v0.1.8-x86_64-apple-darwin.tar.gz"
      sha256 "d20c4eda1f9208dc6bbeaf777b368f225ccf7010144f40af76930843555aedc5"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/agntcy/shadi/releases/download/agntcy-agentbridge-cli-v0.1.8/agentbridge-v0.1.8-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "edff5ef1396f8d0018afe6ad86c4bf1d365e7e2805e780e8c0baa66a73e00724"
    end

    on_intel do
      url "https://github.com/agntcy/shadi/releases/download/agntcy-agentbridge-cli-v0.1.8/agentbridge-v0.1.8-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "68cee1ae63dbff67854f64d50d4c530cbc97723d64d4412aaa16f8e3b11fa712"
    end
  end

  def install
    bin.install "agentbridge"
  end

  test do
    assert_match "agentbridge", shell_output("#{bin}/agentbridge --help")
  end
end
