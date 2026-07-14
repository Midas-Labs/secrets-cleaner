# Homebrew formula for secretsweep.
#
# Install the latest development version straight from this repository:
#   brew install --HEAD ./Formula/secretsweep.rb
#
# Or, once published to a tap (see README "Distributing via Homebrew"):
#   brew install midas-labs/tap/secretsweep
#
# Tagged releases fill in the stable url/sha256 block below (GoReleaser does
# this automatically into the tap; see .goreleaser.yaml).
class Secretsweep < Formula
  desc "Find and purge compromised API keys from Git history"
  homepage "https://github.com/Midas-Labs/secrets-cleaner"
  license "Apache-2.0"

  head "https://github.com/Midas-Labs/secrets-cleaner.git", branch: "main"

  # Stable release (uncomment and update per tagged release):
  # url "https://github.com/Midas-Labs/secrets-cleaner/archive/refs/tags/v2.0.0.tar.gz"
  # sha256 "REPLACE_WITH_TARBALL_SHA256"
  # version "2.0.0"

  depends_on "go" => :build
  depends_on "git-filter-repo"
  depends_on "trivy"

  def install
    cd "secretsweep" do
      system "go", "build", *std_go_args(
        output:  bin/"secretsweep",
        ldflags: "-s -w -X main.version=#{version}",
      )
    end
  end

  test do
    assert_match "secretsweep", shell_output("#{bin}/secretsweep --version")
  end
end
