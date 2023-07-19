#!/bin/sh

# 
# makeDoc.sh (u.blanxd.sshswitch)
# 
# Copyright (c) 2023-06 Blanxd.H <blanxd.h@gmail.com>
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
# 


## debug, not including the docs in debug packages, nor if not run via Theos make, or if this here is set non-zero
[ -n "${DEBUG}" ] || DEBUG=0
DOCDIR=$(dirname "${0}")

[ "${THEOS_SCHEMA}" = "${THEOS_SCHEMA%DEBUG*}" ] || DEBUG=1

if [ -z "${THEOS_PROJECT_DIR}" ]; then
	DEBUG=1
else
	DOCDIR="${THEOS_PROJECT_DIR}/doc"
fi

[ -f "${DOCDIR}/../version.txt" ] && {
	read FULLVERSION < "${DOCDIR}/../version.txt"
}
[ -n "${FULLVERSION}" ] || DEBUG=1
[ "${DEBUG}" = "0" ] && [ "${FULLVERSION}" = "${FULLVERSION#*a}" ] || DEBUG=1

OUTDIR="${DOCDIR}/output"
mkdir -p "${OUTDIR}" || exit 1
STATCMD="stat -f %m" # coreutils
stat --version >/dev/null 2>&1 && STATCMD="stat -c %Y" # macos builtin

#[ -z "${DEBUG}" -o "${DEBUG}" = "0" ] || set > "${OUTDIR}"/makeDoc-set.sh

[ -f "${DOCDIR}/SSHswitch.md" ] && type pandoc >/dev/null 2>&1 && {
	# man
	OUTFTS=$(${STATCMD} "${OUTDIR}/SSHswitch.1" 2>/dev/null)
	[ -n "${OUTFTS}" ] || OUTFTS=0
	[ $(${STATCMD} "${DOCDIR}/SSHswitch.md" 2>/dev/null) -le ${OUTFTS} ] || {
		sed -E -e 's/^(% [^(]+) \(([^)]+)\)( \| version .+)/\1(1) \2\3/' -e 's/^(% [^<|]+) <(<[^>]+>)> \(\[([^]]+)\]\([^)]+\)([^)]+)?\)/\1 \2 (\3)/' "${DOCDIR}/SSHswitch.md" | pandoc -s -t man -o "${OUTDIR}/SSHswitch.1"
	}

	# html
	OUTFTS=$(${STATCMD} "${OUTDIR}/SSHswitch.html" 2>/dev/null)
	[ -n "${OUTFTS}" ] || OUTFTS=0
	[ $(${STATCMD} "${DOCDIR}/SSHswitch.md" 2>/dev/null) -le ${OUTFTS} ] || {
		pandoc --data-dir="${DOCDIR}" -t html --template=SSHswitch-tmpl --toc -o "${OUTDIR}/SSHswitch.html" "${DOCDIR}/SSHswitch.md"
	}

	# pdf, from the html file (need `brew install basictex` in addition to pandoc for this)
	OUTFTS=$(${STATCMD} "${OUTDIR}/SSHswitch.pdf" 2>/dev/null)
	[ -n "${OUTFTS}" ] || OUTFTS=0
	[ $(${STATCMD} "${DOCDIR}/SSHswitch.md" 2>/dev/null) -le ${OUTFTS} ] || {
		pandoc --data-dir="${DOCDIR}" -t pdf --template=SSHswitch-tmpl.latex -V geometry:margin=1.7cm -o "${OUTDIR}/SSHswitch.pdf" "${OUTDIR}/SSHswitch.html"
	}

	# texinfo, for both info and txt
	OUTFTS=$(${STATCMD} "${OUTDIR}/SSHswitch.texinfo" 2>/dev/null)
	[ -n "${OUTFTS}" ] || OUTFTS=0
	[ $(${STATCMD} "${DOCDIR}/SSHswitch.md" 2>/dev/null) -le ${OUTFTS} ] || {
		sed -E -e 's/^   //' -e 's/\*\*//g' -e 's/^# (COPYRIGHT).+/# AUTHORS\/\1/' -e 's/^(Copyright [^<]+)<([^>]+)>/\1\2 reddit.com\/u\/blanxd/' "${DOCDIR}/SSHswitch.md" | pandoc --data-dir="${DOCDIR}" -t texinfo --template=SSHswitch-tmpl --toc --wrap=none | sed -E -e 's/--help/----help/g' -e "s/\@emph\{([^}]+)\}/\`\1\'/g" -e 's/^@chapter AUTHORS.+/& (MIT\/Expat)/' > "${OUTDIR}/SSHswitch.texinfo"
	}
}

[ -f "${OUTDIR}/SSHswitch.texinfo" ] && {
	MAKINFCMD=
	for _mkinf in makeinfo /usr/local/bin/makeinfo /opt/homebrew/opt/texinfo/bin/makeinfo /usr/local/opt/texinfo/bin/makeinfo /opt/local/bin/makeinfo; do
		_mkinfv=$(${_mkinf} --version 2>/dev/null | grep texinfo 2>/dev/null | awk '{ print $4 }' 2>/dev/null)
		_mkinfv="${_mkinfv%%.*}"
		[ -z "${_mkinfv}" ] || [ ${_mkinfv} -lt 5 ] || { # texinfo started supporting UTF-8 @around ver.5, macos(12) is shipping with ver.4.8 from 2004, still?
			MAKINFCMD="${_mkinf}"
			break
		}
	done
	[ -z "${MAKINFCMD}" ] || {

		# info
		OUTFTS=$(${STATCMD} "${OUTDIR}/SSHswitch.info" 2>/dev/null)
		[ -n "${OUTFTS}" ] || OUTFTS=0
		[ $(${STATCMD} "${OUTDIR}/SSHswitch.texinfo" 2>/dev/null) -le ${OUTFTS} ] || {
			${MAKINFCMD} --no-split --fill-column=42 -o "${OUTDIR}/SSHswitch.info" "${OUTDIR}/SSHswitch.texinfo" 2>/dev/null
		}

		# txt
		OUTFTS=$(${STATCMD} "${OUTDIR}/SSHswitch.txt" 2>/dev/null)
		[ -n "${OUTFTS}" ] || OUTFTS=0
		[ $(${STATCMD} "${OUTDIR}/SSHswitch.texinfo" 2>/dev/null) -le ${OUTFTS} ] || {
			${MAKINFCMD} --no-split --plaintext -o "${OUTDIR}/SSHswitch.txt" "${OUTDIR}/SSHswitch.texinfo" 2>/dev/null
		}
	}
}

# Theos staging
[ -z "${THEOS_PROJECT_DIR}" ] || {
	JBSYSROOT=""
	[ "${THEOS_PACKAGE_ARCH}" = "iphoneos-arm64" ] && JBSYSROOT="/var/jb"

	rm -rf "${THEOS_PROJECT_DIR}"/layout/var/mobile/Documents/SSHswitch 2>/dev/null # v.1.0.x setups
	rm -rf "${THEOS_PROJECT_DIR}"/layout/var/mobile/Documents/SSHswitch-doc/* 2>/dev/null
	rm -rf "${THEOS_PROJECT_DIR}"/layout/var/jb/var/mobile/Documents/SSHswitch-doc/* 2>/dev/null
	INFDOC=
	MANDOC=
	MOBDOC=

	[ "${DEBUG}" = "0" ] && {

		# info
		[ -f "${OUTDIR}/SSHswitch.info" ] && mkdir -p "${THEOS_PROJECT_DIR}/layout${JBSYSROOT}/usr/share/info" && \
			cp -fp "${OUTDIR}/SSHswitch.info" "${THEOS_PROJECT_DIR}/layout${JBSYSROOT}/usr/share/info/SSHswitch.info" && \
				INFDOC=1

		# man
		[ -f "${OUTDIR}/SSHswitch.1" ] && mkdir -p "${THEOS_PROJECT_DIR}/layout${JBSYSROOT}/usr/share/man/man1" && \
			cp -fp "${OUTDIR}/SSHswitch.1" "${THEOS_PROJECT_DIR}/layout${JBSYSROOT}/usr/share/man/man1/SSHswitch.1" && \
				MANDOC=1

		# non-cli
		[ -f "${OUTDIR}/SSHswitch.html" -o -f "${OUTDIR}/SSHswitch.pdf" -o -f "${OUTDIR}/SSHswitch.txt" ] && \
		mkdir -p "${THEOS_PROJECT_DIR}/layout${JBSYSROOT}/var/mobile/Documents/SSHswitch-doc" && {
			# the Files.app doesn't show the filename extensions, so let's have 2 so they are visible.

			[ -f "${OUTDIR}/SSHswitch.html" ] && \
				cp -fp "${OUTDIR}/SSHswitch.html" "${THEOS_PROJECT_DIR}/layout${JBSYSROOT}/var/mobile/Documents/SSHswitch-doc/SSHswitch.html.html" && \
				MOBDOC=1
	
			[ -f "${OUTDIR}/SSHswitch.pdf" ] && \
				cp -fp "${OUTDIR}/SSHswitch.pdf" "${THEOS_PROJECT_DIR}/layout${JBSYSROOT}/var/mobile/Documents/SSHswitch-doc/SSHswitch.pdf.pdf" && \
				MOBDOC=1
	
			[ -f "${OUTDIR}/SSHswitch.txt" ] && \
				cp -fp "${OUTDIR}/SSHswitch.txt" "${THEOS_PROJECT_DIR}/layout${JBSYSROOT}/var/mobile/Documents/SSHswitch-doc/SSHswitch.txt.txt" && \
				MOBDOC=1
			
			[ -z "${MOBDOC}" ] || {
				# Files.app on older iOS (11,12) might not display .md files.
				cp -fp "${DOCDIR}/about_SSHswitch_doc.md" "${THEOS_PROJECT_DIR}/layout${JBSYSROOT}/var/mobile/Documents/SSHswitch-doc/about_SSHswitch_doc.txt"
				chmod 0444 "${THEOS_PROJECT_DIR}/layout${JBSYSROOT}"/var/mobile/Documents/SSHswitch-doc/*
			}
		}
	}

	[ -n "${MANDOC}" ] || {
		rm -rf "${THEOS_PROJECT_DIR}/layout${JBSYSROOT}/usr/share/man/man1" 2>/dev/null
		pushd "${THEOS_PROJECT_DIR}/layout${JBSYSROOT}" >/dev/null 2>&1 && {
			rmdir -p usr/share/man 2>/dev/null
			popd >/dev/null
		}
	}
	[ -n "${INFDOC}" ] || {
		rm -rf "${THEOS_PROJECT_DIR}/layout${JBSYSROOT}/usr/share/info" 2>/dev/null
		pushd "${THEOS_PROJECT_DIR}/layout${JBSYSROOT}" >/dev/null 2>&1 && {
			rmdir -p usr/share 2>/dev/null
			popd >/dev/null
		}
	}
	[ -n "${MOBDOC}" ] || {
		rm -rf "${THEOS_PROJECT_DIR}/layout${JBSYSROOT}/var/mobile/Documents/SSHswitch-doc" 2>/dev/null
		pushd "${THEOS_PROJECT_DIR}/layout${JBSYSROOT}" >/dev/null 2>&1 && {
			rmdir -p var/mobile/Documents 2>/dev/null
			popd >/dev/null
		}
	}
}

