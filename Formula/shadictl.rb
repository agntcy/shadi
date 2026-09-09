# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

class Shadictl < Formula
  desc "Command-line interface for SHADI policy, secrets, memory, and SLIM operations."
  homepage "https://github.com/agntcy/shadi"
  version "0.1.7"
  license "Apache-2.0"
  head "https://github.com/agntcy/shadi.git", branch: "main"

  on_macos do
    on_arm do
      url "https://github.com/agntcy/shadi/releases/download/agntcy-shadi-cli-v0.1.7/shadictl-v0.1.7-aarch64-apple-darwin.tar.gz"
      sha256 "3d7239ec89e51f74ac05cc0144ce660252f6b3ab21e793510fe4d9cd2110a410"
    end

    on_intel do
      url "https://github.com/agntcy/shadi/releases/download/agntcy-shadi-cli-v0.1.7/shadictl-v0.1.7-x86_64-apple-darwin.tar.gz"
      sha256 "4155acc9c6cf31c899ee770d7622b1d820b4e56f08e1e6609c4af2fd6cd7cb6c"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/agntcy/shadi/releases/download/agntcy-shadi-cli-v0.1.7/shadictl-v0.1.7-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "3610b2eac7f2c91832de8b18cebf16ad8101eb8f4af0570208587c38402a9a6b"
    end

    on_intel do
      url "https://github.com/agntcy/shadi/releases/download/agntcy-shadi-cli-v0.1.7/shadictl-v0.1.7-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "3b825e5e2353f22d20a57fd9a378f55c33b0803fbcd6d675dd39f3dbc7ab043a"
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
