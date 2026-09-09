# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

class Agentbridge < Formula
  desc "CLI binary for the agentbridge general-purpose agent interconnect."
  homepage "https://github.com/agntcy/shadi"
  version "0.1.5"
  license "Apache-2.0"
  head "https://github.com/agntcy/shadi.git", branch: "main"

  on_macos do
    on_arm do
      url "https://github.com/agntcy/shadi/releases/download/agntcy-agentbridge-cli-v0.1.5/agentbridge-v0.1.5-aarch64-apple-darwin.tar.gz"
      sha256 "e1dbf468883ea303a8809b4962a579e5b1671a9791759a4dc82536c4df5f05f2"
    end

    on_intel do
      url "https://github.com/agntcy/shadi/releases/download/agntcy-agentbridge-cli-v0.1.5/agentbridge-v0.1.5-x86_64-apple-darwin.tar.gz"
      sha256 "4722bea68b0babf6aeabac409a178fd28ad3d317c95b36c76d3cab27dd7b7bd4"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/agntcy/shadi/releases/download/agntcy-agentbridge-cli-v0.1.5/agentbridge-v0.1.5-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "8aaa05db4be21da45971391ea56ba0590d0ab5d7eb493e82db50c55bcb1a8ac8"
    end

    on_intel do
      url "https://github.com/agntcy/shadi/releases/download/agntcy-agentbridge-cli-v0.1.5/agentbridge-v0.1.5-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "4621b4b4bfa50854379c01877811c8f5bd8f93802fbfc6acebaf89cfe28fa9b6"
    end
  end

  def install
    bin.install "agentbridge"
  end

  test do
    assert_match "agentbridge", shell_output("#{bin}/agentbridge --help")
  end
end
