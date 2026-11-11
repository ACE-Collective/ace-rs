// ACE3 javascript deobfuscator -- reconstructed from sandbox trace
// source: /js-deobfuscator/input/00000000-0000-4000-8000-000000000000/blob_redirect.js
// webcrack static pass: applied

new Blob(["<html><body><a href=\"https://login.evil.example/signin\">sign in</a></body></html>"], {"type":"text/html"});
URL.createObjectURL(new Blob(..., {"type":"text/html"}));
window.location.replace(URL.createObjectURL(new Blob(..., {"type":"text/html"})));

// --- deobfuscated source (post-webcrack) ---
if (false) {
var page = "<html><body><a href=\"https://login.evil.example/signin\">sign in</a></body></html>";
var blob = new Blob([page], {
  type: "text/html"
});
window.location.replace(URL.createObjectURL(blob));
}
