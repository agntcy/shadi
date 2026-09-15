# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

class Shadictl < Formula
  desc "Command-line interface for SHADI policy, secrets, memory, and SLIM operations."
  homepage "https://github.com/agntcy/shadi"
  version "0.1.10"
  license "Apache-2.0"
  head "https://github.com/agntcy/shadi.git", branch: "main"

  on_macos do
    on_arm do
      url "https://github.com/agntcy/shadi/releases/download/agntcy-shadi-cli-v0.1.10/shadictl-v0.1.10-aarch64-apple-darwin.tar.gz"
      sha256 "08b0f8455d2640c29eadd323716793beb0e1efcda343a3e9c9dd43b77f19836c"
    end

    on_intel do
      url "https://github.com/agntcy/shadi/releases/download/agntcy-shadi-cli-v0.1.10/shadictl-v0.1.10-x86_64-apple-darwin.tar.gz"
      sha256 "0ba8aff1bb43f47915f3ca7ec1f11db6b783f4e61502ab885a90f8f8931617fc"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/agntcy/shadi/releases/download/agntcy-shadi-cli-v0.1.10/shadictl-v0.1.10-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "f093064f4a34399e18a7dc589cc393e2b8bb603052ed75137b8f693abf45dcc5"
    end

    on_intel do
      url "https://github.com/agntcy/shadi/releases/download/agntcy-shadi-cli-v0.1.10/shadictl-v0.1.10-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "bb52a0255f7aa756574c93dffa2ef78792afc73bef998d5b200e7f4d6b77d352"
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
