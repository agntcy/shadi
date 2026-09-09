# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

class Shadictl < Formula
  desc "Command-line interface for SHADI policy, secrets, memory, and SLIM operations."
  homepage "https://github.com/agntcy/shadi"
  version "0.1.8"
  license "Apache-2.0"
  head "https://github.com/agntcy/shadi.git", branch: "main"

  on_macos do
    on_arm do
      url "https://github.com/agntcy/shadi/releases/download/agntcy-shadi-cli-v0.1.8/shadictl-v0.1.8-aarch64-apple-darwin.tar.gz"
      sha256 "4fd8b12a22cedc1f09dbef8a8cac023bbde8b99c35baf4afe2a82d04589f3d5a"
    end

    on_intel do
      url "https://github.com/agntcy/shadi/releases/download/agntcy-shadi-cli-v0.1.8/shadictl-v0.1.8-x86_64-apple-darwin.tar.gz"
      sha256 "055b1526e50d78e346de424d387caa7b6b7169537902b26a419ff1779cae9e56"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/agntcy/shadi/releases/download/agntcy-shadi-cli-v0.1.8/shadictl-v0.1.8-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "1af835d7eb2f381c89f4a5cc6964a761f74eb5237d3a2fba4e735f8a03a2ab37"
    end

    on_intel do
      url "https://github.com/agntcy/shadi/releases/download/agntcy-shadi-cli-v0.1.8/shadictl-v0.1.8-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "9daffb713308dc3c8c803e022d24fd0156b64a12b6380ea54896af2b7f195104"
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
