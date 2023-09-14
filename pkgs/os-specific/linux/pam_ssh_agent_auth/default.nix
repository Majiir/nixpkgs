{ lib, stdenv, fetchpatch, fetchFromGitHub, pam, openssl, perl }:

stdenv.mkDerivation rec {
  pname = "pam_ssh_agent_auth";
  version = "0.10.4";

  src = fetchFromGitHub {
    owner = "jbeverly";
    repo = "pam_ssh_agent_auth";
    rev = "pam_ssh_agent_auth-${version}";
    sha256 = "YD1R8Cox0UoNiuWleKGzWSzxJ5lhDRCB2mZPp9OM6Cs=";
  };

  ed25519-donna = fetchFromGitHub {
    owner = "floodyberry";
    repo = "ed25519-donna";
    rev = "8757bd4cd209cb032853ece0ce413f122eef212c";
    sha256 = "ETFpIaWQnlYG8ZuDG2dNjUJddlvibB4ukHquTFn3NZM=";
  };

  buildInputs = [ pam openssl perl ];

  patches = [
    # Allow multiple colon-separated authorized keys files to be
    # specified in the file= option.
    ./multiple-key-files.patch
    ./edcsa-crash-fix.patch

    (fetchpatch {
      name = "fix-openssl-headers-match.patch";
      url = "https://github.com/jbeverly/pam_ssh_agent_auth/commit/674f1b017e5cf299334aff6000fb67c52b2b8934.patch";
      sha256 = "sha256-XxSThDtw+licTmsN7BxrpAMyZNJicX+xEM+UiJONipY=";
    })
  ];

  configureFlags = [
    # Make sure it can find ed25519-donna
    "--with-cflags=-I$PWD"
  ];

  prePatch = "cp -r ${ed25519-donna}/. ed25519-donna/.";

  enableParallelBuilding = true;

  meta = {
    homepage = "https://github.com/jbeverly/pam_ssh_agent_auth";
    description = "PAM module for authentication through the SSH agent";
    maintainers = [ lib.maintainers.eelco ];
    platforms = lib.platforms.linux;
  };
}
