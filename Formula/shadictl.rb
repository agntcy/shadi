# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

class Shadictl < Formula
  desc "Command-line interface for SHADI policy, secrets, memory, and SLIM operations."
  homepage "https://github.com/agntcy/shadi"
  url "https://github.com/agntcy/shadi/archive/refs/tags/agntcy-shadi-cli-v0.1.1.tar.gz"
  sha256 "2de2d8417cf5c7c708f767960dc13e230f18fb84b42a7dfa3f135e41cc6fe4be"
  license "Apache-2.0"
  head "https://github.com/agntcy/shadi.git", branch: "main"

  depends_on "pkgconf" => :build
  depends_on "rust" => :build
  depends_on "nettle"
  depends_on "openssl@3"
  depends_on "python@3.12"

  def install
    ENV["OPENSSL_DIR"] = Formula["openssl@3"].opt_prefix
    ENV["PYO3_PYTHON"] = Formula["python@3.12"].opt_bin/"python3.12"

    system "cargo", "install", "--locked", "--path", "crates/shadictl", *std_cargo_args
  end

  test do
    assert_match "shadictl", shell_output("#{bin}/shadictl --help")
  end
end
