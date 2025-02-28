# Copyright 2025 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=8

# Description of the package
DESCRIPTION="TritJS: A ternary logic arithmetic library implemented in CWEB"
HOMEPAGE="https://copyleftsystems.com/tritjs" # Placeholder; replace with actual URL if available
SRC_URI="https://example.com/tritjs-${PV}.cweb" # Placeholder; adjust to real source location

# Licensing and package metadata
LICENSE="GPL-2" # Assuming GPL-2; adjust based on intended license
SLOT="0"
KEYWORDS="~amd64 ~x86"
IUSE="tri doc" # 'tri' enables ternary logic; 'doc' adds typeset documentation

# Dependencies: cweb required for 'tri' (ternary logic) or 'doc' (typeset docs)
DEPEND="
    tri? ( dev-tex/cweb )
    doc? ( dev-tex/cweb )
"
RDEPEND="${DEPEND}"
BDEPEND=""

# Working directory for build
S="${WORKDIR}"

src_unpack() {
    # Unpack the single CWEB file from DISTDIR to WORKDIR
    mkdir -p "${S}" || die "Failed to create source directory"
    cp "${DISTDIR}/${P}.cweb" "${S}/tritjs.cweb" || die "Failed to copy cweb file"
}

src_prepare() {
    default

    # Generate a basic README for user instructions
    cat > "${S}/README" << 'EOF'
TritJS 1.0 - Ternary Logic Library

Overview:
  TritJS is a C-based library for ternary (base-3) arithmetic, built from a CWEB source.
  It supports addition, subtraction, multiplication, and division of trit arrays (0, 1, 2).

USE Flags:
  - tri: Enables full ternary logic functionality. Without it, a minimal version is installed.
  - doc: Generates and installs a typeset DVI document from the CWEB source.

Installation:
  - With ternary logic: `USE="tri" emerge -av tritjs`
  - Minimal version: `emerge -av tritjs`
  - With typeset docs: `USE="doc" emerge -av tritjs`

Usage:
  - Run `tritjs` after installation:
    - With 'tri': Executes example ternary operations (e.g., 12₃ + 21₃ = 110₃).
    - Without 'tri': Prints version and a note about disabled ternary logic.

Documentation:
  - Source: /usr/share/doc/tritjs-1.0/tritjs.cweb
  - Typeset (if 'doc' enabled): /usr/share/doc/tritjs-1.0/tritjs.dvi

For issues, see ${HOMEPAGE} or contact the maintainers.
EOF
}

src_configure() {
    # No configure step; CWEB compilation handled in src_compile
    :
}

src_compile() {
    if use tri; then
        # Build full ternary logic version
        ctangle "${S}/tritjs.cweb" || die "ctangle failed"
        ecc -o tritjs tritjs.c || die "Compilation failed"
    else
        # Build minimal version without ternary logic
        echo '#include <stdio.h>' > tritjs.c
        echo 'int main() { printf("TritJS %s (ternary logic disabled)\\n", "'${PV}'"); return 0; }' >> tritjs.c
        ecc -o tritjs tritjs.c || die "Compilation failed"
    fi
}

src_install() {
    # Install the binary (full or minimal)
    dobin tritjs

    # Install basic documentation
    dodoc "${S}/tritjs.cweb" "${S}/README"

    # Optional typeset documentation with 'doc' USE flag
    if use doc; then
        cweave "${S}/tritjs.cweb" || die "cweave failed"
        tex "${S}/tritjs.tex" || die "tex failed"
        dodoc "${S}/tritjs.dvi"
    fi
}

pkg_postinst() {
    # Post-install instructions
    if use tri; then
        elog "TritJS with ternary logic is installed. Run 'tritjs' to test arithmetic operations."
        elog "See /usr/share/doc/${PF}/README for usage details."
    else
        elog "TritJS installed without ternary logic (minimal version)."
        elog "Enable the 'tri' USE flag for full functionality. See /usr/share/doc/${PF}/README."
    fi
    elog "Source documentation available at /usr/share/doc/${PF}/tritjs.cweb"
    if use doc; then
        elog "Typeset documentation installed at /usr/share/doc/${PF}/tritjs.dvi"
    fi
}
