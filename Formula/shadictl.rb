# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

class Shadictl < Formula
  desc "Command-line interface for SHADI policy, secrets, memory, and SLIM operations."
  homepage "https://github.com/agntcy/shadi"
  version "0.1.11"
  license "Apache-2.0"
  head "https://github.com/agntcy/shadi.git", branch: "main"

  on_macos do
    on_arm do
      url "https://github.com/agntcy/shadi/releases/download/agntcy-shadi-cli-v0.1.11/shadictl-v0.1.11-aarch64-apple-darwin.tar.gz"
      sha256 "8af1c676a962f1e167049ea0d377be5334b59d6fd90c828f7169a332178eb1ca"
    end

    on_intel do
      url "https://github.com/agntcy/shadi/releases/download/agntcy-shadi-cli-v0.1.11/shadictl-v0.1.11-x86_64-apple-darwin.tar.gz"
      sha256 "d06c495cd495d91d7d495d2982ab611074652d1478c96c985de049683eb525c3"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/agntcy/shadi/releases/download/agntcy-shadi-cli-v0.1.11/shadictl-v0.1.11-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "17e252d9d1a7dd19923c17da84b8481640431c47e32fce861f806c819a3039a0"
    end

    on_intel do
      url "https://github.com/agntcy/shadi/releases/download/agntcy-shadi-cli-v0.1.11/shadictl-v0.1.11-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "9166908b9ce69106ac3757f8ab1e471004e64573cf7c5b213d6f3b63f50e6326"
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
