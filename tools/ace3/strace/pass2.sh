#!/bin/sh
# Second pass: bigger inputs for tools whose threads depend on the input, and the same tools
# under a seccomp filter that allows threads and kills a new process (filter.py).
set -u
W=/work
O=/out
mkdir -p $W $O
cd $W
cp /ace3/app/help/content/svs/images/alert-context.png $W/big.png
cp /ace3/tests/saq/modules/test_file_analysis/sample_pdf_with_qr_code.pdf $W/qr.pdf
cp /ace3/tests/saq/modules/test_file_analysis_full/pdf/Payment_Advice.pdf $W/p.pdf
cp /ace3/tests/saq/modules/file_analysis/test_java/VxUGJsAplRNavewkjKujp.class $W/c.class
cp /ace3/tests/saq/modules/test_file_analysis/hello_autoit.exe $W/autoit.exe
cp /ace3/tests/saq/modules/test_file_analysis_full/exe/cmd-upx.exe $W/upx.exe
cp /ace3/tests/saq/test_ocr/small.png $W/o.png
cp /ace3/tests/saq/modules/file_analysis/test_pcap/network.pcap $W/n.pcap
/venv/bin/python3 -I -c '
import sys
data = b"".join(bytes.fromhex(l.strip()) for l in open(sys.argv[1]))
open("/work/dn.exe", "wb").write(data)' /ace3/tests/saq/modules/test_file_analysis/6346eea9dff4eac53113fc2ba3b8a497.hex
gs -q -sDEVICE=pngalpha -o $W/qr-%d.png -r144 $W/qr.pdf
head -c 64000000 /dev/urandom > $W/rand.bin
7z a -mx=5 -mmt=on $W/big.7z $W/rand.bin >/dev/null

summarize() {
  f=$O/$1.strace
  threads=$(grep -E 'clone3?\(' $f | grep -c CLONE_THREAD)
  procs=$(grep -E 'clone3?\(|vfork\(|fork\(' $f | grep -vc CLONE_THREAD)
  printf '%-26s exit=%-4s threads=%-4s processes=%-4s\n' "$1" "$2" "$threads" "$procs"
}
t() {
  name=$1; shift
  rm -rf $W/out-$name; mkdir -p $W/out-$name
  (cd $W/out-$name && strace -f -qq -e trace=clone,clone3,fork,vfork,execve -o $O/$name.strace "$@" >$O/$name.stdout 2>$O/$name.stderr)
  summarize $name $?
}
t tesseract-big-limit1   env OMP_THREAD_LIMIT=1 tesseract $W/big.png stdout --oem 1 --psm 3
t tesseract-big-nolimit  tesseract $W/big.png stdout --oem 1 --psm 3
for p in $W/qr-*.png; do t zbarimg-$(basename $p .png) zbarimg -q --raw --nodbus $p; done
t zbarimg-limit1         env MAGICK_THREAD_LIMIT=1 OMP_THREAD_LIMIT=1 zbarimg -q --raw --nodbus $W/qr-1.png
t qr-opencv-nolimit      /venv/bin/python3 -I /ace3/bin/qr_decode_opencv.py $W/qr-1.png
t 7z-x-big               7z x -o$W/out-7z-x-big/x $W/big.7z
t gs-pngalpha-all        gs -sDEVICE=pngalpha -o page-%d.png -r144 $W/qr.pdf
grep -h . $O/zbarimg-qr-1.stdout | head -3 | sed 's/^/  zbarimg found: /'
ldd /usr/bin/zbarimg | grep -iE 'magick|gomp' | sed 's/^/  zbarimg links /'

echo
echo "under seccomp: threads allowed, a new process kills (SIGSYS = 159)"
F="/venv/bin/python3 -I /s/filter.py"
# runs a command under the filter, then without it, and says whether stdout and the files it
# wrote are the same both ways (a run whose output names a time or a path can differ)
s() {
  name=$1; shift
  rm -rf $W/f-$name $W/p-$name; mkdir -p $W/f-$name $W/p-$name
  (cd $W/f-$name && "$@" >$O/f-$name.stdout 2>$O/f-$name.stderr)
  code=$?
  shift 3; [ "$1" = "--no-threads" ] && shift
  (cd $W/p-$name && "$@" >$O/p-$name.stdout 2>/dev/null)
  same=different
  cmp -s $O/f-$name.stdout $O/p-$name.stdout && diff -r $W/f-$name $W/p-$name >/dev/null && same=same
  printf '%-26s exit=%-4s stdout=%s bytes, %s with and without the filter\n' "$name" "$code" "$(wc -c < $O/f-$name.stdout)" "$same"
}
s control-sh-forks       $F /bin/sh -c '/bin/true; echo after'
s control-sh-no-fork     $F /bin/sh -c 'echo builtin only'
s exiftool               $F /usr/bin/exiftool -j -G -n $W/p.pdf
s cfr                    $F /usr/bin/java -Xmx1g -XX:CompressedClassSpaceSize=128m -XX:ReservedCodeCacheSize=128m -XX:-UsePerfData -jar /usr/local/bin/cfr.jar $W/c.class
s unautoit-list          $F /usr/local/bin/unautoit list $W/autoit.exe
s de4dot-detect          $F /usr/bin/env DOTNET_GCHeapHardLimit=0x40000000 DOTNET_GCRegionRange=0x80000000 /opt/de4dotEx/de4dot -d $W/dn.exe
s ilspycmd               $F /usr/bin/env DOTNET_GCHeapHardLimit=0x40000000 DOTNET_GCRegionRange=0x80000000 /opt/dotnet/ilspycmd -il --disable-updatecheck -o . $W/dn.exe
s tesseract-big          $F /usr/bin/tesseract $W/big.png stdout --oem 1 --psm 3
s zbarimg                $F /usr/bin/zbarimg -q --raw --nodbus $W/qr-1.png
s upx-d                  $F /usr/bin/upx -d -ounpacked.exe $W/upx.exe
s gs-pdfwrite            $F /usr/bin/gs -sDEVICE=pdfwrite -o output.pdf -f $W/p.pdf
s pdftotext              $F /usr/bin/pdftotext $W/p.pdf output.txt
s 7z-x-big               $F /usr/lib/7zip/7z x -ox $W/big.7z
s tshark-json            $F /usr/bin/tshark -n -r $W/n.pcap -T json -Y 'dns || http.request' -e frame.number -e dns.qry.name

echo
echo "under seccomp: no thread and no process (the parser's filter), SIGSYS = 159"
F="/venv/bin/python3 -I /s/filter.py --no-threads"
s nt-exiftool            $F /usr/bin/exiftool -j -G -n $W/p.pdf
s nt-upx-d               $F /usr/bin/upx -d -ounpacked.exe $W/upx.exe
s nt-gs-pdfwrite         $F /usr/bin/gs -sDEVICE=pdfwrite -o output.pdf -f $W/p.pdf
s nt-gs-pngalpha         $F /usr/bin/gs -sDEVICE=pngalpha -o page-%d.png -r144 $W/qr.pdf
s nt-pdftotext           $F /usr/bin/pdftotext $W/p.pdf output.txt
s nt-pdfinfo             $F /usr/bin/pdfinfo $W/qr.pdf
s nt-tesseract-limit1    $F /usr/bin/env OMP_THREAD_LIMIT=1 /usr/bin/tesseract $W/big.png stdout --oem 1 --psm 3
s nt-zbarimg-limit1      $F /usr/bin/env MAGICK_THREAD_LIMIT=1 OMP_THREAD_LIMIT=1 /usr/bin/zbarimg -q --raw --nodbus $W/qr-1.png
s nt-7z-x-big            $F /usr/lib/7zip/7z x -ox $W/big.7z
s nt-7z-x-big-mmt1       $F /usr/lib/7zip/7z x -mmt=1 -ox $W/big.7z
s nt-cfr                 $F /usr/bin/java -jar /usr/local/bin/cfr.jar $W/c.class
cmp $O/f-zbarimg.stdout $O/zbarimg-qr-1.stdout && echo "  zbarimg under the filter printed what it printed without it"
cmp $O/f-cfr.stdout $O/cfr.stdout 2>/dev/null; true
