# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

class Shadictl < Formula
  desc "Command-line interface for SHADI policy, secrets, memory, and SLIM operations."
  homepage "https://github.com/agntcy/shadi"
  version "0.1.5"
  license "Apache-2.0"
  head "https://github.com/agntcy/shadi.git", branch: "main"

  on_macos do
    on_arm do
      url "https://github.com/agntcy/shadi/releases/download/agntcy-shadi-cli-v0.1.5/shadictl-v0.1.5-aarch64-apple-darwin.tar.gz"
      sha256 "d87d9f10cc9448210c6022ad22bd2ce93bc9d90cf1707d2e4efc377010f83dd9"
    end

    on_intel do
      url "https://github.com/agntcy/shadi/releases/download/agntcy-shadi-cli-v0.1.5/shadictl-v0.1.5-x86_64-apple-darwin.tar.gz"
      sha256 "144e026053764c9a2379db947204616cd6281713c53759f23fdc2e449688f928"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/agntcy/shadi/releases/download/agntcy-shadi-cli-v0.1.5/shadictl-v0.1.5-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "47693a6d84c90b67a08ca962ff09b6cb29f32f0acba55044618cd56077a80972"
    end

    on_intel do
      url "https://github.com/agntcy/shadi/releases/download/agntcy-shadi-cli-v0.1.5/shadictl-v0.1.5-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "6c6100554dc70e3fb008ee3b10b96f247e9478826b04d667482d907bad6966e5"
    end

    depends_on "patchelf" => :build
    depends_on "openssl@3"
  end

  def install
    bin.install "shadictl"

    return unless OS.linux?

    system "patchelf", "--set-rpath", Formula["openssl@3"].opt_lib, bin/"shadictl"
  end

  test do
    assert_match "shadictl", shell_output("#{bin}/shadictl --help")
  end
end
