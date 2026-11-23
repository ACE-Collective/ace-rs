"""Records what ace3's is_javascript_file answers (node 24's `node --check`, then grep) for the
JavaScript cases of crates/ace-mod-files: hand-written ones and mutations of them. Run in ace3's
dev container with /venv/bin/python3 -I js_oracle.py OUT.json; javascript.rs's tests read OUT.json.

Each case is written as case.js and checked as ace3 checks a file already named .js; the mutations
are seeded, so the cases are the same each run."""
import base64, json, os, random, subprocess, sys, tempfile

sys.path.insert(0, "/opt/ace")
from saq.modules.file_analysis.is_file_type import is_javascript_file  # noqa: E402

HAND = [
    # scripts and modules
    "var a = 1;", "let a = 1; const b = 2;", "function f() { return 1 }", "return 5;", "await 1;",
    "import x from 'y';", "export const a = 1;", "export default function () {}", "import.meta.url",
    "return 5;\nimport x from 'y';", "await x; var y = require(1)", "const await = 1;", "var await;",
    "new.target", "#!/usr/bin/env node\nvar a", "﻿var a = 1", "<!-- hi\nvar a=1;", "var a = 1; --> x",
    "with (a) {}", "'use strict'; with (a) {}", "'use strict'; var eval = 1;", "'use strict'; 010",
    "010", "'\\08'", "'use strict'; '\\08'", "`\\08`", "delete x", "'use strict'; delete x",
    "let a; let a;", "var a; var a;", "let a; var a;", "const a;", "let let = 1;", "var let = 1;",
    "let x; { let x; }", "function f(a, a) {}", "'use strict'; function f(a, a) {}", "(a, a) => 1",
    "class A { constructor() {} constructor() {} }", "class A { #x; m() { this.#y } }",
    "class A { #x; #x; }", "class A { static #x = 1; m() { return A.#x } }", "class A extends B { constructor() { super() } }",
    "function f() { super() }", "class A { m() { super.x } }", "label: label: 1", "a: { break a; }",
    "break;", "continue;", "while (1) { break; }", "x: while (1) { continue y; }",
    "for (let x of y) {}", "for (let x in y) {}", "for (var x = 1 in y) {}", "for await (x of y) {}",
    "async function f() { for await (x of y) {} }", "async () => await 1", "function* g() { yield 1 }",
    "function* g() { yield* g() }", "yield = 1", "'use strict'; yield = 1", "async function f() { var await }",
    "a?.b?.[c]?.(d)", "a ?? b || c", "(a ?? b) || c", "a **= 2", "-a ** 2", "(-a) ** 2", "1_000_000",
    "1__0", "0x_1", "10n", "0b102", "0o78", "1e", ".5", "5.", "0.0000001", "'\\u{110000}'",
    "'\\u{10FFFF}'", "'\\x4'", "/a/v", "/[a&&b]/v", "/(?<n>a)\\k<n>/", "/(?<n>a)(?<n>b)/", "/(?<n>a)|(?<n>b)/",
    "/[/", "/a/gg", "/a/x", "/(?i:a)/", "/\\p{L}/u", "/\\p{Nope}/u", "/{1}/", "/a{1}/u", "/\\c/",
    "/(?=a)*/", "/(?=a)*/u", "x = /a/ / 2", "`a${b}c`", "`a${`b${c}`}`", "tag`\\unicode`", "`\\unicode`",
    "({a, b} = c)", "({a = 1} = c)", "({a = 1})", "[a, ...b, c] = d", "[...a] = b", "({...a, b} = c)",
    "({ __proto__: 1, __proto__: 2 })", "({ __proto__: 1, ['__proto__']: 2 })", "({ get a(x) {} })",
    "({ set a() {} })", "({ async *m() {} })", "x => { 'use strict'; }", "(a = 1) => { 'use strict'; }",
    "function f(a = 1) { 'use strict' }", "if (a) function f() {}", "'use strict'; if (a) function f() {}",
    "while (a) function f() {}", "label: function f() {}", "'use strict'; label: function f() {}",
    "try {} catch {}", "try {} catch (e) { let e; }", "try {} catch (e) { var e; }", "try {} catch ([e]) { var e; }",
    "try {}", "throw\nnew Error()", "a\n++b", "a\n(b)", "let \n x = 1", "var a = 1 2", "var a = ;",
    "x = { a: 1, }", "f(a, b,)", "f(,)", "function f(a,) {}", "(a,) => 1", "(...a,) => 1",
    "using x = y;", "{ using x = y; }", "await using x = y;", "@dec class A {}", "class A { @dec m() {} }",
    "class A { accessor x = 1 }", "let a: number = 1;", "interface A {}", "enum E { A }", "<div/>",
    "var a = <b>c</b>;", "import x from 'y' with { type: 'json' };", "import x from 'y' assert { type: 'json' };",
    "export * as ns from 'm';", "import { 'a-b' as c } from 'm';", "export { a as 'b-c' };",
    "import defer * as x from 'y';", "import source x from 'y';", "x = import('y')", "x = import.meta",
    "import('y', { with: {} })", "#x in obj", "class A { #x; m(o) { return #x in o } }",
    "class A { static { this.x = 1 } }", "class A { static { await } }", "class A { static { return } }",
    "class A { static { arguments } }", "class A { x = arguments }", "function f() { arguments = 1 }",
    "'use strict'; arguments = 1", "eval = 1", "'use strict'; eval = 1", "0 = 1", "a + 1 = 2", "++a++",
    "a?.b = 1", "new a?.b", "a?.`x`", "super.x", "x = { m() { super.x } }", "new.target.x", "import.meta = 1",
    "async function f() { await = 1 }", "function f() { await = 1 }", "async (await) => 1",
    "function* g() { function yield() {} }", "function* g() { var yield }", "a b", "' '", "' '",
    "/* unterminated", "// comment only", "", " ", "\n\n", ";", "{}", "({})", "[]", "x", "1 +", "'unterminated",
    "\"a\\\nb\"", "`unterminated", "a = 1\n/b/g.test(c)", "a = b\n/hi/g", "var \\u0061 = 1", "var a\\u{62} = 1",
    "var \\u0030 = 1", "var ℮ = 1", "var 𐐀 = 1", "var a‌ = 1", "var  a = 1", "var a = '\x00'",
    "\x00", "var a = 1;\x00", "for (;;) {}", "do x; while (y) z", "do x\nwhile (y) z", "if (a) else b",
    "switch (a) { case 1: let x; case 2: let x; }", "switch (a) { default: default: }",
    "function f() { 'use strict'; with (a) {} }", "function f() { 'use asm'; }", "debugger;",
    "html = '<!--' + x", "x\n-->y", "/*\n*/-->y", "a = b ? c : d ? e : f", "a ? b", "(a, b)", "()",
    "() => {}", "async\n() => {}", "async () \n=> {}", "() \n=> {}", "a = async function* () { yield* await b }",
    "Object.defineProperty(exports, '__esModule', { value: true });", "module.exports = function () {}",
    "require('fs').readFileSync('/etc/passwd')", "eval('var a = 1')", "new Function('a', 'return a')",
    "app['s' + 'etTimeOut']('x', 1)", "WScript.Echo('hi')", "var x = new ActiveXObject('WScript.Shell'); x.Run('cmd')",
    "this.print({bUI: true})", "%DebugPrint(x)",
]


def mutations(rnd, base, count):
    tokens = ["(", ")", "{", "}", "[", "]", ";", ",", ".", "=", "=>", "'", '"', "`", "/", "*", "\n", " ",
              "var", "let", "async", "await", "yield", "return", "import", "export", "class", "#", "@", "?.", "??",
              "\\", "${", "<!--", "-->", " ", "﻿", "\x00", "1", "a"]
    out = []
    for _ in range(count):
        s = list(base)
        for _ in range(rnd.randint(1, 4)):
            op = rnd.random()
            p = rnd.randrange(len(s) + 1)
            if op < 0.4 or not s:
                s[p:p] = list(rnd.choice(tokens))
            elif op < 0.8:
                del s[p:p + rnd.randint(1, 3)]
            else:
                if s:
                    s[min(p, len(s) - 1)] = rnd.choice(tokens)
        out.append("".join(s))
    return out


SEEDED = [
    "function invoice(a, b) {\n  var total = a + b;\n  return total.toFixed(2);\n}\nmodule.exports = invoice;\n",
    "const run = async (url) => {\n  const r = await fetch(url);\n  return r.json().then((j) => j.data);\n};\n",
    "import { a } from './a.js';\nexport class B extends a {\n  #x = 1;\n  get x() { return this.#x }\n}\n",
    "var s = new ActiveXObject('WScript.Shell');\ntry { s.Run('cmd /c ' + x, 0) } catch (e) { WScript.Quit(1) }\n",
    "var o = {a: [1, 2, {b: `t${c}`}], 'd': /re[a-z]+/gi, e: x => x ** 2};\nfor (let k in o) if (o[k]) delete o[k];\n",
]


def main(out_path):
    rnd = random.Random(20261108)
    sources = list(HAND)
    for base in SEEDED:
        sources.append(base)
        sources.extend(mutations(rnd, base, 120))
    cases = []
    with tempfile.TemporaryDirectory(dir="/tmp/ace-rs-js") as work:
        for i, source in enumerate(sources):
            data = source.encode("utf-8", "surrogatepass")
            path = os.path.join(work, f"case{i}.js")
            with open(path, "wb") as fp:
                fp.write(data)
            check = subprocess.run(["node", "--check", path], capture_output=True)
            cases.append({
                "source": base64.b64encode(data).decode(),
                "node_check": check.returncode == 0,
                "is_javascript_file": is_javascript_file(path),
            })
            os.unlink(path)
    with open(out_path, "w") as fp:
        json.dump({"node": subprocess.run(["node", "--version"], capture_output=True, text=True).stdout.strip(),
                   "cases": cases}, fp, indent=0)


if __name__ == "__main__":
    main(sys.argv[1])
