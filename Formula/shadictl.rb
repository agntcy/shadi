# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

class Shadictl < Formula
  desc "Command-line interface for SHADI policy, secrets, memory, and SLIM operations."
  homepage "https://github.com/agntcy/shadi"
  version "0.1.9"
  license "Apache-2.0"
  head "https://github.com/agntcy/shadi.git", branch: "main"

  on_macos do
    on_arm do
      url "https://github.com/agntcy/shadi/releases/download/agntcy-shadi-cli-v0.1.9/shadictl-v0.1.9-aarch64-apple-darwin.tar.gz"
      sha256 "66f166ccf45413db6b925e3698582cffe8e9c9bbeae4c4aa132fd40a2114f68b"
    end

    on_intel do
      url "https://github.com/agntcy/shadi/releases/download/agntcy-shadi-cli-v0.1.9/shadictl-v0.1.9-x86_64-apple-darwin.tar.gz"
      sha256 "f9237255d72d9ac4103cf175e5fe268b3150da1c0cce6ec17572c942658faa64"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/agntcy/shadi/releases/download/agntcy-shadi-cli-v0.1.9/shadictl-v0.1.9-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "432ffc1e199ed171d26b6493a9f5af4bc7f1c5cdb8c2a1817d75d8ee30603725"
    end

    on_intel do
      url "https://github.com/agntcy/shadi/releases/download/agntcy-shadi-cli-v0.1.9/shadictl-v0.1.9-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "78e7e4f658e43f3375345d80b5567a0c93cc71600081b632676abfce1952f821"
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
