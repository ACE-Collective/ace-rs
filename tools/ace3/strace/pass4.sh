#!/bin/sh
# Fourth pass: the tools whose modules go to crates, for the record.
set -u
cd /tmp
cp /ace3/tests/saq/modules/test_file_analysis/doc.docx d.docx
echo 'var x = 1; eval("x")' > s.js
ssdeep -s d.docx > h.txt
for c in "ssdeep -m h.txt d.docx" "file -b -L d.docx" "file -b --mime-type -L d.docx" "node --check s.js" "perl /ace3/bin/jscript.decode.pl s.js"; do
  strace -f -qq -e trace=clone,clone3,fork,vfork,execve -o o.strace $c >/dev/null 2>&1; e=$?
  printf '%-40s exit=%-3s threads=%-3s processes=%s\n' "$c" $e "$(grep -E 'clone3?\(' o.strace | grep -c CLONE_THREAD)" "$(grep -E 'clone3?\(|fork\(' o.strace | grep -vc CLONE_THREAD)"
done
