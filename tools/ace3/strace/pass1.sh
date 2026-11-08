#!/bin/sh
# Runs each external tool ace3's modules start, on a sample, under
#   strace -f -e trace=clone,clone3,fork,vfork,execve
# in a throwaway container of ace3's own image (ace3:latest), and prints for each run how many
# threads (clone with CLONE_THREAD) and processes (clone without it, fork, vfork) it started and
# which programs it exec'd. Samples come from ace3's tests (read-only mount at /ace3) and a DMG at /d, which `run` makes on macOS.
set -u
A=/ace3/tests/saq/modules
W=/work
O=/out
mkdir -p $W $O
cd $W

cp $A/file_analysis/test_java/VxUGJsAplRNavewkjKujp.class $W/c.class
cp $A/test_file_analysis_full/exe/cmd-upx.exe $W/upx.exe
cp $A/test_file_analysis/hello_autoit.exe $W/autoit.exe
cp $A/test_file_analysis/sample_pdf_with_qr_code.pdf $W/qr.pdf
cp $A/test_file_analysis_full/pdf/Payment_Advice.pdf $W/p.pdf
cp $A/test_file_analysis/doc.docx $W/d.docx
cp $A/test_file_analysis_full/ace/dhl_report.ace $W/a.ace
cp /ace3/tests/saq/test_ocr/small.png $W/o.png
cp /ace3/tests/saq/modules/file_analysis/test_pcap/network.pcap $W/n.pcap
[ -f /d/t.dmg ] && cp /d/t.dmg $W/t.dmg
/venv/bin/python3 -I -c '
import sys
data = b"".join(bytes.fromhex(l.strip()) for l in open(sys.argv[1]))
open("/work/dn.exe", "wb").write(data)' $A/test_file_analysis/6346eea9dff4eac53113fc2ba3b8a497.hex
echo "the password is Passw0rd" > $W/payload.txt
7z a -tzip -pPassw0rd $W/z.zip $W/payload.txt >/dev/null
/venv/bin/python3 -I -c '
import pikepdf
pdf = pikepdf.open("/work/p.pdf")
pdf.save("/work/enc.pdf", encryption=pikepdf.Encryption(user="Passw0rd", owner="Passw0rd"))'
printf 'nope\nPassw0rd\n' > $W/words.txt
J=/opt/tools/john-1.9.0-jumbo-1/run

summarize() {
  name=$1
  f=$O/$name.strace
  threads=$(grep -E 'clone3?\(' $f | grep -c CLONE_THREAD)
  procs=$(grep -E 'clone3?\(|vfork\(|fork\(' $f | grep -vc CLONE_THREAD)
  execs=$(grep -E 'execve\(' $f | grep -v ENOENT | sed -E 's/^[0-9]+ +execve\("([^"]+)".*/\1/' | sort | uniq -c | awk '{printf "%s%s x%s", sep, $2, $1; sep=", "}')
  printf '%-22s exit=%-4s threads=%-4s processes=%-4s exec: %s\n' "$name" "$2" "$threads" "$procs" "$execs"
}

t() {
  name=$1; shift
  rm -rf $W/out-$name; mkdir -p $W/out-$name
  (cd $W/out-$name && strace -f -qq -e trace=clone,clone3,fork,vfork,execve -o $O/$name.strace "$@" >$O/$name.stdout 2>$O/$name.stderr)
  summarize $name $?
}

t exiftool-pdf       exiftool -j -G -n $W/p.pdf
t exiftool-docx      exiftool -j -G -n $W/d.docx
t cfr                java -Xmx1g -XX:CompressedClassSpaceSize=128m -XX:ReservedCodeCacheSize=128m -XX:-UsePerfData -jar /usr/local/bin/cfr.jar $W/c.class
t cfr-1cpu           java -Xmx1g -XX:CompressedClassSpaceSize=128m -XX:ReservedCodeCacheSize=128m -XX:-UsePerfData -XX:ActiveProcessorCount=1 -XX:+UseSerialGC -XX:CICompilerCount=1 -XX:TieredStopAtLevel=1 -jar /usr/local/bin/cfr.jar $W/c.class
t upx-t              upx -t $W/upx.exe
t upx-d              upx -d -ounpacked.exe $W/upx.exe
t unautoit-list      unautoit list $W/autoit.exe
t unautoit-extract   unautoit extract-all --output-dir $W/out-unautoit-extract/x $W/autoit.exe
t de4dot-detect      env DOTNET_GCHeapHardLimit=0x40000000 DOTNET_GCRegionRange=0x80000000 /opt/de4dotEx/de4dot -d $W/dn.exe
t de4dot-clean       env DOTNET_GCHeapHardLimit=0x40000000 DOTNET_GCRegionRange=0x80000000 /opt/de4dotEx/de4dot $W/dn.exe -o deobfuscated
t ilspycmd           env DOTNET_GCHeapHardLimit=0x40000000 DOTNET_GCRegionRange=0x80000000 /opt/dotnet/ilspycmd -il --disable-updatecheck -o . $W/dn.exe
t tesseract          env OMP_THREAD_LIMIT=1 tesseract $W/o.png stdout --oem 1 --psm 3
t tesseract-no-limit tesseract $W/o.png stdout --oem 1 --psm 3
t pdfinfo            pdfinfo $W/qr.pdf
t gs-pngalpha        gs -sDEVICE=pngalpha -o page-%d.png -r144 -dFirstPage=1 -dLastPage=1 $W/qr.pdf
t gs-pdfwrite        gs -sDEVICE=pdfwrite -o output.pdf -f $W/p.pdf
gs -q -sDEVICE=pngalpha -o $W/qr-1.png -r144 -dFirstPage=1 -dLastPage=1 $W/qr.pdf
t zbarimg            zbarimg -q --raw --nodbus $W/qr-1.png
t qr-opencv          env OPENBLAS_NUM_THREADS=1 /venv/bin/python3 -I /ace3/bin/qr_decode_opencv.py $W/qr-1.png
t pdftotext          pdftotext $W/p.pdf output.txt
t dmg2img            dmg2img $W/t.dmg image.img
t 7z-l-img           7z l $W/out-dmg2img/image.img
t 7z-x-member        7z x -o$W/out-7z-x-member/x $W/out-dmg2img/image.img T/T.app/Contents/MacOS/run
t unace-l            unace l $W/a.ace
t unace-x            unace x -y -o $W/a.ace
t zip2john           $J/zip2john $W/z.zip
$J/zip2john $W/z.zip > $W/z.hash 2>/dev/null
t john-zip           $J/john --session=john --pot=john.pot --wordlist=$W/words.txt $W/z.hash
t john-show          $J/john --pot=$W/out-john-zip/john.pot --show $W/z.hash
t pdf2john           perl $J/pdf2john.pl $W/enc.pdf
t capinfos           capinfos -M -S $W/n.pcap
t tshark-stats       tshark -n -r $W/n.pcap -q -z io,stat,0 -z endpoints,ip -z conv,tcp
t tshark-json        tshark -n -r $W/n.pcap -T json -Y 'dns || http.request' -e frame.number -e dns.qry.name --export-objects http,objects/http

echo
echo "versions:"
exiftool -ver | sed 's/^/  exiftool /'
java -version 2>&1 | head -1 | sed 's/^/  /'
upx --version | head -1 | sed 's/^/  /'
tesseract --version 2>&1 | head -1 | sed 's/^/  /'
gs --version | sed 's/^/  gs /'
pdftotext -v 2>&1 | head -1 | sed 's/^/  /'
zbarimg --version | sed 's/^/  zbarimg /'
7z i | sed -n 2p | sed 's/^/  /'
dmg2img 2>&1 | head -2 | tail -1 | sed 's/^/  /'
$J/john 2>&1 | head -1 | sed 's/^/  /'
tshark --version | head -1 | sed 's/^/  /'
ldd $(which tesseract) | grep -i gomp | sed 's/^/  tesseract links /'
ldd $J/john | grep -i gomp | sed 's/^/  john links /'
file /usr/local/bin/unautoit | sed 's/^/  /'
