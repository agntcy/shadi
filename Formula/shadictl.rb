# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

class Shadictl < Formula
  desc "Command-line interface for SHADI policy, secrets, memory, and SLIM operations."
  homepage "https://github.com/agntcy/shadi"
  version "0.1.4"
  license "Apache-2.0"
  head "https://github.com/agntcy/shadi.git", branch: "main"

  on_macos do
    on_arm do
      url "https://github.com/agntcy/shadi/releases/download/agntcy-shadi-cli-v0.1.4/shadictl-v0.1.4-aarch64-apple-darwin.tar.gz"
      sha256 "fac7114f9c438e7a2c464335d535d02adb87d66f9231c35d3f5be6e5e861c5b6"
    end

    on_intel do
      url "https://github.com/agntcy/shadi/releases/download/agntcy-shadi-cli-v0.1.4/shadictl-v0.1.4-x86_64-apple-darwin.tar.gz"
      sha256 "113efdd5ef6a28800c44b6fe892f88da611b5d53655f5abccfe67c08bac6c6dc"
    end
  end

  on_linux do
    # The Linux build links libcrypto.so.3 with no rpath, so it resolves
    # against the system loader path rather than a Homebrew prefix. Built
    # from source here until the released binary carries its own rpath.
    url "https://github.com/agntcy/shadi/archive/refs/tags/agntcy-shadi-cli-v0.1.4.tar.gz"
    sha256 "2f586f9c1d8ec7e8082749b94b6b4691f830eb22a780a02d975a5e744ccc2a92"

    depends_on "pkgconf" => :build
    depends_on "rust" => :build
    depends_on "nettle"
    depends_on "openssl@3"
    depends_on "python@3.12"
  end

  def install
    if OS.mac?
      bin.install "shadictl"
    else
      ENV["OPENSSL_DIR"] = Formula["openssl@3"].opt_prefix
      ENV["PYO3_PYTHON"] = Formula["python@3.12"].opt_bin/"python3.12"

      # std_cargo_args already passes --locked and --path.
      system "cargo", "install", *std_cargo_args(path: "crates/shadictl")
    end
  end

  test do
    assert_match "shadictl", shell_output("#{bin}/shadictl --help")
  end
end
