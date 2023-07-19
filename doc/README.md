# documentation for SSHswitch

Things needed are:
* [pandoc](https://pandoc.org/), for MacOS `brew install pandoc` or on Linux use your corresponding package manager.
* [TeX Live](https://www.tug.org/texlive/) for making the .pdf. For MacOS this would be `brew install basictex`, or on Linux look for `pandoc-pdf` or a separate `texlive-pdftex` or similar package. [https://pandoc.org/MANUAL.html#creating-a-pdf](https://pandoc.org/MANUAL.html#creating-a-pdf).
* [Texinfo](https://www.gnu.org/software/texinfo/) for making the .info. MacOS 12 has some very old one bundled, should really use a newer one (ver >= 5), ie. `brew install texinfo`. The makeDoc.sh script tries to find one on the system which is newer, if none found then it doesn't create the .info and .txt files.

The doc source `SSHswitch.md` was specifically made for `pandoc`, a few things probably don't render universally well by your regular MarkDown readers/converters.

`makeDoc.sh` may be run manually to see what the result would be (in the resulting `output/` subdir). When the Makefile runs it, the results get copied into the package (unless it's an alpha build).

