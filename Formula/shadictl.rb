# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

class Shadictl < Formula
  desc "Command-line interface for SHADI policy, secrets, memory, and SLIM operations."
  homepage "https://github.com/agntcy/shadi"
  version "0.1.6"
  license "Apache-2.0"
  head "https://github.com/agntcy/shadi.git", branch: "main"

  on_macos do
    on_arm do
      url "https://github.com/agntcy/shadi/releases/download/agntcy-shadi-cli-v0.1.6/shadictl-v0.1.6-aarch64-apple-darwin.tar.gz"
      sha256 "1867daa832a727cb1a363a97fe54961ecc8b6d817424b6a04779ca27fc5cc128"
    end

    on_intel do
      url "https://github.com/agntcy/shadi/releases/download/agntcy-shadi-cli-v0.1.6/shadictl-v0.1.6-x86_64-apple-darwin.tar.gz"
      sha256 "7977cd10a3f74eb21591a7eec22e32695c71808537473275fdfc6cdc02b045b4"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/agntcy/shadi/releases/download/agntcy-shadi-cli-v0.1.6/shadictl-v0.1.6-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "8b1aff5d55c547314b5576e732ddb3ce24bdf0c4d1ead0ae9d322a4c0ee8e571"
    end

    on_intel do
      url "https://github.com/agntcy/shadi/releases/download/agntcy-shadi-cli-v0.1.6/shadictl-v0.1.6-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "c2a9ce5541cef8613ca641ad5652b2fdd832c53e5c13459a42e2077f626d4d7d"
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
