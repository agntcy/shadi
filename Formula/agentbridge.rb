# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

class Agentbridge < Formula
  desc "CLI binary for the agentbridge general-purpose agent interconnect."
  homepage "https://github.com/agntcy/shadi"
  version "0.1.3"
  license "Apache-2.0"
  head "https://github.com/agntcy/shadi.git", branch: "main"

  on_macos do
    on_arm do
      url "https://github.com/agntcy/shadi/releases/download/agntcy-agentbridge-cli-v0.1.3/agentbridge-v0.1.3-aarch64-apple-darwin.tar.gz"
      sha256 "65d18f4582dfe7bd6fd6e776c209e979eb4a47e179503fade9aa16f3a9881b38"
    end

    on_intel do
      url "https://github.com/agntcy/shadi/releases/download/agntcy-agentbridge-cli-v0.1.3/agentbridge-v0.1.3-x86_64-apple-darwin.tar.gz"
      sha256 "77292b752a2f8a92f435baf28952cbffd3168dd36b03a55fcc0c5bdc7a8c6549"
    end
  end

  on_linux do
    # The Linux build links libcrypto.so.3 with no rpath, so it resolves
    # against the system loader path rather than a Homebrew prefix. Built
    # from source here until the released binary carries its own rpath.
    url "https://github.com/agntcy/shadi/archive/refs/tags/agntcy-agentbridge-cli-v0.1.3.tar.gz"
    sha256 "0decd71c02d385025594eaddc39a47aa6927a088067583ba56b5fa04859ea919"

    depends_on "pkgconf" => :build
    depends_on "rust" => :build
    depends_on "nettle"
    depends_on "openssl@3"
    depends_on "python@3.12"
  end

  def install
    if OS.mac?
      bin.install "agentbridge"
    else
      ENV["OPENSSL_DIR"] = Formula["openssl@3"].opt_prefix
      ENV["PYO3_PYTHON"] = Formula["python@3.12"].opt_bin/"python3.12"

      # std_cargo_args already passes --locked and --path.
      system "cargo", "install", *std_cargo_args(path: "crates/agentbridge_cli")
    end
  end

  test do
    assert_match "agentbridge", shell_output("#{bin}/agentbridge --help")
  end
end
