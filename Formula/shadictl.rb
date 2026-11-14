# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

class Shadictl < Formula
  desc "Command-line interface for SHADI policy, secrets, memory, and SLIM operations."
  homepage "https://github.com/agntcy/shadi"
  version "0.2.0"
  license "Apache-2.0"
  head "https://github.com/agntcy/shadi.git", branch: "main"

  on_macos do
    on_arm do
      url "https://github.com/agntcy/shadi/releases/download/agntcy-shadi-cli-v0.2.0/shadictl-v0.2.0-aarch64-apple-darwin.tar.gz"
      sha256 "1532af503a0d183acf81fabd03c3bd6401401a231f8eb69f0b08188feeb32caf"
    end

    on_intel do
      url "https://github.com/agntcy/shadi/releases/download/agntcy-shadi-cli-v0.2.0/shadictl-v0.2.0-x86_64-apple-darwin.tar.gz"
      sha256 "330875a081acda3b7f0bd58bc1f2a9e5518df43971f240717b02db96ae70f356"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/agntcy/shadi/releases/download/agntcy-shadi-cli-v0.2.0/shadictl-v0.2.0-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "5f9734c75be48d3a20923b2d1b6afc8e4de04bf2a64d95294337afd30278bb56"
    end

    on_intel do
      url "https://github.com/agntcy/shadi/releases/download/agntcy-shadi-cli-v0.2.0/shadictl-v0.2.0-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "ae83bc27c1f0143acb9f56c326affa8532a7f8d7512a7e811cde090fabacdfa6"
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
