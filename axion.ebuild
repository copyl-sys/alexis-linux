# Copyright 2025 Alexis Linux Contributors
# Distributed under the terms of the GNU General Public License v3

EAPI=8

DESCRIPTION="Axion: Ternary Package Manager (CISA Inspired Guardian AI)"
HOMEPAGE="https://alexislinux.org/axion"
SRC_URI="https://alexislinux.org/src/${P}.cweb"

LICENSE="GPL-3"
SLOT="0"
KEYWORDS="~amd64 ~arm ~riscv"
IUSE="ai doc"

DEPEND="
    ai? (
        sci-libs/tensorflow-alexis
        dev-libs/openblas
        app-misc/ollama
        net-analyzer/security-onion
        sys-apps/systemd
        net-libs/libpcap
        app-forensics/sleuthkit
    )
"
RDEPEND="${DEPEND}"
BDEPEND="
    ai? ( dev-util/cmake )
    doc? ( dev-tex/cweb )
"

S="${WORKDIR}/${P}"

src_unpack() {
    einfo "Unpacking Axion source..."
    unpack "${A}"
    cd "${S}" || die "Failed to enter ${S}"
}

src_prepare() {
    default
    use ai && einfo "AI functionality enabled."
    use doc && einfo "Documentation will be generated."
}

src_configure() {
    if use ai; then
        CFLAGS+=" -DAXION"
        export CFLAGS
    fi
}

src_compile() {
    einfo "Compiling Axion..."
    ctangle "${S}/axion.cweb" || die "ctangle failed"
    
    emake || die "Compilation failed"

    if use ai; then
        einfo "Compiling Axion AI weight helper..."
        ${CC} ${CFLAGS} "${S}/axion_weight.c" -o axion_weight || die "Failed to compile axion_weight"
    fi
}

src_install() {
    einfo "Installing Axion..."

    # Install library and headers
    insinto /usr/lib/axion
    doins libaxion.a || die "Failed to install libaxion.a"
    
    insinto /usr/include/axion
    doins axion.h || die "Failed to install axion.h"

    # Install documentation
    dodoc README "${S}/axion.cweb"
    use doc && dodoc "${S}/axion.dvi"

    if use ai; then
        einfo "Installing Axion AI components..."

        exeinto /usr/bin
        doexe "${S}/axion" || die "Failed to install Axion executable"

        exeinto /usr/libexec
        doexe "${S}/axion_weight" || die "Failed to install Axion AI weight helper"

        insinto /etc/axion
        doins "${S}/ai_config.conf" || die "Failed to install AI configuration"
    fi
}

pkg_postinst() {
    if use ai; then
        elog "Axion installed with AI support."
        elog "Use 'axion install <package>' for AI-enhanced package management."
    fi
}
