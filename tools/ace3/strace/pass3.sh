#!/bin/sh
# Third pass: the page that holds the QR code, the files .NET tools write under the filter, and
# whether a thread limit changes a tool's output.
set -u
W=/work; mkdir -p $W; cd $W
cp /ace3/tests/saq/modules/test_file_analysis/sample_pdf_with_qr_code.pdf qr.pdf
cp /ace3/app/help/content/svs/images/alert-context.png big.png
cp /ace3/tests/saq/modules/file_analysis/test_java/VxUGJsAplRNavewkjKujp.class c.class
/venv/bin/python3 -I -c '
import sys
data = b"".join(bytes.fromhex(l.strip()) for l in open(sys.argv[1]))
open("/work/dn.exe", "wb").write(data)' /ace3/tests/saq/modules/test_file_analysis/6346eea9dff4eac53113fc2ba3b8a497.hex
gs -q -sDEVICE=pngalpha -o qr-%d.png -r144 qr.pdf
T="/venv/bin/python3 -I /s/filter.py"
N="$T --no-threads"
zbarimg -q --raw --nodbus qr-2.png > z-plain.txt; echo "zbarimg plain exit=$?"
$T /usr/bin/zbarimg -q --raw --nodbus qr-2.png > z-threads.txt; echo "zbarimg threads-filter exit=$?"
$N /usr/bin/env MAGICK_THREAD_LIMIT=1 OMP_THREAD_LIMIT=1 /usr/bin/zbarimg -q --raw --nodbus qr-2.png > z-single.txt; echo "zbarimg no-thread-filter, limit 1 exit=$?"
strace -f -qq -e trace=clone,clone3 -o z.strace env MAGICK_THREAD_LIMIT=1 OMP_THREAD_LIMIT=1 zbarimg -q --raw --nodbus qr-2.png >/dev/null; echo "zbarimg limit 1 clones: $(grep -c clone z.strace)"
cmp z-plain.txt z-threads.txt && cmp z-plain.txt z-single.txt && echo "zbarimg: same output three ways: $(head -c 60 z-plain.txt)"
tesseract big.png stdout --oem 1 --psm 3 2>/dev/null > t-plain.txt
OMP_THREAD_LIMIT=1 tesseract big.png stdout --oem 1 --psm 3 2>/dev/null > t-1.txt
cmp t-plain.txt t-1.txt && echo "tesseract: same text with OMP_THREAD_LIMIT=1 ($(wc -c < t-1.txt) bytes)"
java -jar /usr/local/bin/cfr.jar c.class > cfr-plain.java
$T /usr/bin/java -jar /usr/local/bin/cfr.jar c.class > cfr-threads.java
cmp cfr-plain.java cfr-threads.java && echo "cfr: same output under the threads filter"
mkdir il && cd il && $T /usr/bin/env DOTNET_GCHeapHardLimit=0x40000000 DOTNET_GCRegionRange=0x80000000 /opt/dotnet/ilspycmd -il --disable-updatecheck -o . /work/dn.exe; echo "ilspycmd threads-filter exit=$? wrote: $(ls | tr '\n' ' ') $(cat * | wc -c) bytes"; cd ..
mkdir de && cd de && cp /work/dn.exe . && $T /usr/bin/env DOTNET_GCHeapHardLimit=0x40000000 DOTNET_GCRegionRange=0x80000000 /opt/de4dotEx/de4dot dn.exe -o deobfuscated > out.txt; echo "de4dot clean threads-filter exit=$? wrote: $(ls | tr '\n' ' ')"; cd ..
mkdir de2 && cd de2 && cp /work/dn.exe . && $N /usr/bin/env DOTNET_GCHeapHardLimit=0x40000000 /opt/de4dotEx/de4dot -d dn.exe; echo "de4dot no-thread-filter exit=$?"; cd ..
