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
    # The Linux build links libcrypto.so.3 with no rpath, so it resolves
    # against the system loader path rather than a Homebrew prefix. Built
    # from source here until the released binary carries its own rpath.
    url "https://github.com/agntcy/shadi/archive/refs/tags/agntcy-shadi-cli-v0.1.5.tar.gz"
    sha256 "f98042226f148c1267fe929f5b7669e35c9df4b82786bfd0bd02a062061f92fe"

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
