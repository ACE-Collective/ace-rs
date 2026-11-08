//! A parsed template made into one that runs as Jinja2 does, and the paths ace3 finds in it.
//!
//! minijinja's operators, literals and lookups are its own: `[]` is an immutable list folded into
//! a constant, `+` adds whatever it can, and `true ~ 1` prints `true1`. [`rebuild`] copies the
//! parsed tree with each of those replaced by a call to a function of [`super::ops`], which does
//! what Python does, so `{% set seen = [] %}` is a fresh list each time, as Python's literal is.
//! It also turns literal text into constants, so every byte of output passes the formatter and
//! its bound, and refuses what Jinja2 refuses before rendering: `{% do %}`, which needs an
//! extension ace3 doesn't load, and a filter or test that doesn't exist outside an `{% if %}` or
//! an inline if (Jinja2's compile-time check).
//!
//! [`paths`] is ace3's `_extract_paths` (`saq/query/template_rendering.py`): every name and
//! attribute or constant-subscript chain in the order Jinja2's `find_all` walks its own tree,
//! kept where no longer chain begins with it.

use minijinja::machinery::Span;
use minijinja::machinery::ast::{self, CallArg, Expr, Spanned, Stmt};
use minijinja::value::Value;

/// One segment of a path: a name or attribute, or a constant subscript.
#[derive(Debug, Clone, PartialEq)]
pub enum Segment {
    Name(String),
    Index(i128),
}

pub struct Check<'f> {
    pub filters: &'f dyn Fn(&str) -> bool,
    pub tests: &'f dyn Fn(&str) -> bool,
    /// Marks each arm of each `{% if %}` and inline if, for [`super::coverage`].
    pub cover: bool,
}

fn var<'a>(id: &'static str, span: Span) -> Expr<'a> {
    Expr::Var(Spanned::new(ast::Var { id }, span))
}

fn konst<'a>(value: Value, span: Span) -> Expr<'a> {
    Expr::Const(Spanned::new(ast::Const { value }, span))
}

fn call<'a>(func: &'static str, args: Vec<Expr<'a>>, span: Span) -> Expr<'a> {
    Expr::Call(Spanned::new(
        ast::Call {
            expr: var(func, span),
            args: args.into_iter().map(CallArg::Pos).collect(),
        },
        span,
    ))
}

struct Rebuild<'c, 'f> {
    check: &'c Check<'f>,
}

/// The template with Python's semantics, or why Jinja2 wouldn't compile it.
pub fn rebuild<'a>(stmt: &Stmt<'a>, check: &Check<'_>) -> Result<Stmt<'a>, String> {
    Rebuild { check }.stmt(stmt, false)
}

impl Rebuild<'_, '_> {
    fn body<'a>(&self, body: &[Stmt<'a>], soft: bool) -> Result<Vec<Stmt<'a>>, String> {
        body.iter().map(|s| self.stmt(s, soft)).collect()
    }

    fn stmt<'a>(&self, stmt: &Stmt<'a>, soft: bool) -> Result<Stmt<'a>, String> {
        Ok(match stmt {
            Stmt::Template(t) => Stmt::Template(Spanned::new(
                ast::Template {
                    children: self.body(&t.children, soft)?,
                },
                t.span(),
            )),
            Stmt::EmitExpr(e) => Stmt::EmitExpr(Spanned::new(
                ast::EmitExpr {
                    expr: self.expr(&e.expr, soft)?,
                },
                e.span(),
            )),
            Stmt::EmitRaw(r) => Stmt::EmitExpr(Spanned::new(
                ast::EmitExpr {
                    expr: konst(Value::from(r.raw), r.span()),
                },
                r.span(),
            )),
            Stmt::ForLoop(f) => Stmt::ForLoop(Spanned::new(
                ast::ForLoop {
                    target: self.target(&f.target)?,
                    // minijinja iterates none as empty, where Python raises
                    iter: call("%iter", vec![self.expr(&f.iter, soft)?], f.iter.span()),
                    filter_expr: f
                        .filter_expr
                        .as_ref()
                        .map(|e| self.expr(e, false))
                        .transpose()?,
                    recursive: f.recursive,
                    body: self.body(&f.body, false)?,
                    else_body: self.body(&f.else_body, soft)?,
                },
                f.span(),
            )),
            Stmt::IfCond(i) => {
                let mut true_body = self.body(&i.true_body, true)?;
                let mut false_body = self.body(&i.false_body, true)?;
                if self.check.cover {
                    let id = i.span().start_offset * 2;
                    true_body.insert(0, self.mark(id, i.span()));
                    false_body.insert(0, self.mark(id + 1, i.span()));
                }
                Stmt::IfCond(Spanned::new(
                    ast::IfCond {
                        expr: self.expr(&i.expr, true)?,
                        true_body,
                        false_body,
                    },
                    i.span(),
                ))
            }
            Stmt::WithBlock(w) => Stmt::WithBlock(Spanned::new(
                ast::WithBlock {
                    assignments: w
                        .assignments
                        .iter()
                        .map(|(t, e)| Ok((self.target(t)?, self.expr(e, soft)?)))
                        .collect::<Result<_, String>>()?,
                    body: self.body(&w.body, false)?,
                },
                w.span(),
            )),
            Stmt::Set(s) => Stmt::Set(Spanned::new(
                ast::Set {
                    target: self.target(&s.target)?,
                    expr: self.expr(&s.expr, soft)?,
                },
                s.span(),
            )),
            Stmt::SetBlock(s) => Stmt::SetBlock(Spanned::new(
                ast::SetBlock {
                    target: self.target(&s.target)?,
                    filter: s.filter.as_ref().map(|e| self.expr(e, false)).transpose()?,
                    body: self.body(&s.body, false)?,
                },
                s.span(),
            )),
            Stmt::AutoEscape(a) => Stmt::AutoEscape(Spanned::new(
                ast::AutoEscape {
                    enabled: self.expr(&a.enabled, soft)?,
                    body: self.body(&a.body, soft)?,
                },
                a.span(),
            )),
            Stmt::FilterBlock(f) => Stmt::FilterBlock(Spanned::new(
                ast::FilterBlock {
                    filter: self.expr(&f.filter, false)?,
                    body: self.body(&f.body, false)?,
                },
                f.span(),
            )),
            Stmt::Macro(m) => Stmt::Macro(Spanned::new(self.macro_decl(m)?, m.span())),
            Stmt::CallBlock(c) => Stmt::CallBlock(Spanned::new(
                ast::CallBlock {
                    call: Spanned::new(self.call_node(&c.call, soft)?, c.call.span()),
                    macro_decl: Spanned::new(self.macro_decl(&c.macro_decl)?, c.macro_decl.span()),
                },
                c.span(),
            )),
            Stmt::Do(_) => return Err("Encountered unknown tag 'do'.".to_owned()),
            Stmt::Block(b) => Stmt::Block(Spanned::new(
                ast::Block {
                    name: b.name,
                    required: b.required,
                    body: self.body(&b.body, false)?,
                },
                b.span(),
            )),
            // ace3's environment has no loader, so these fail when they run, as minijinja's do
            // without one; `ignore missing` doesn't save an include there, so it's dropped
            Stmt::Extends(x) => Stmt::Extends(Spanned::new(
                ast::Extends {
                    name: self.expr(&x.name, soft)?,
                },
                x.span(),
            )),
            Stmt::Include(i) => Stmt::Include(Spanned::new(
                ast::Include {
                    name: self.expr(&i.name, soft)?,
                    ignore_missing: false,
                },
                i.span(),
            )),
            Stmt::Import(i) => Stmt::Import(Spanned::new(
                ast::Import {
                    expr: self.expr(&i.expr, soft)?,
                    name: self.target(&i.name)?,
                },
                i.span(),
            )),
            Stmt::FromImport(i) => Stmt::FromImport(Spanned::new(
                ast::FromImport {
                    expr: self.expr(&i.expr, soft)?,
                    names: i
                        .names
                        .iter()
                        .map(|(n, a)| {
                            Ok((
                                self.target(n)?,
                                a.as_ref().map(|a| self.target(a)).transpose()?,
                            ))
                        })
                        .collect::<Result<_, String>>()?,
                },
                i.span(),
            )),
        })
    }

    fn mark<'a>(&self, id: u32, span: Span) -> Stmt<'a> {
        super::coverage::declare(id);
        Stmt::EmitExpr(Spanned::new(
            ast::EmitExpr {
                expr: call("%cover", vec![konst(Value::from(id), span)], span),
            },
            span,
        ))
    }

    fn marked<'a>(&self, id: u32, expr: Expr<'a>, span: Span) -> Expr<'a> {
        if !self.check.cover {
            return expr;
        }
        super::coverage::declare(id);
        call("%covered", vec![konst(Value::from(id), span), expr], span)
    }

    fn macro_decl<'a>(&self, m: &ast::Macro<'a>) -> Result<ast::Macro<'a>, String> {
        Ok(ast::Macro {
            name: m.name,
            args: m
                .args
                .iter()
                .map(|a| self.target(a))
                .collect::<Result<_, _>>()?,
            defaults: m
                .defaults
                .iter()
                .map(|d| self.expr(d, false))
                .collect::<Result<_, _>>()?,
            body: self.body(&m.body, false)?,
        })
    }

    /// An assignment's target, where an attribute is a namespace's (`{% set ns.x = 1 %}`) and
    /// stays as it is.
    fn target<'a>(&self, e: &Expr<'a>) -> Result<Expr<'a>, String> {
        Ok(match e {
            Expr::Var(v) => Expr::Var(Spanned::new(ast::Var { id: v.id }, v.span())),
            Expr::Tuple(t) => Expr::Tuple(Spanned::new(
                ast::Tuple {
                    items: t
                        .items
                        .iter()
                        .map(|i| self.target(i))
                        .collect::<Result<_, _>>()?,
                },
                t.span(),
            )),
            Expr::List(l) => Expr::List(Spanned::new(
                ast::List {
                    items: l
                        .items
                        .iter()
                        .map(|i| self.target(i))
                        .collect::<Result<_, _>>()?,
                },
                l.span(),
            )),
            Expr::GetAttr(g) => Expr::GetAttr(Spanned::new(
                ast::GetAttr {
                    expr: self.target(&g.expr)?,
                    name: g.name,
                },
                g.span(),
            )),
            other => self.expr(other, false)?,
        })
    }

    fn args<'a>(&self, args: &[CallArg<'a>], soft: bool) -> Result<Vec<CallArg<'a>>, String> {
        args.iter()
            .map(|a| {
                Ok(match a {
                    CallArg::Pos(e) => CallArg::Pos(self.expr(e, soft)?),
                    CallArg::Kwarg(name, e) => CallArg::Kwarg(name, self.expr(e, soft)?),
                    CallArg::PosSplat(e) => CallArg::PosSplat(self.expr(e, soft)?),
                    CallArg::KwargSplat(e) => CallArg::KwargSplat(self.expr(e, soft)?),
                })
            })
            .collect()
    }

    fn call_node<'a>(&self, c: &ast::Call<'a>, soft: bool) -> Result<ast::Call<'a>, String> {
        // a method call keeps its attribute, so minijinja calls the method on the object
        let callee = match &c.expr {
            Expr::GetAttr(g) => Expr::GetAttr(Spanned::new(
                ast::GetAttr {
                    expr: self.expr(&g.expr, soft)?,
                    name: g.name,
                },
                g.span(),
            )),
            Expr::Var(v) => Expr::Var(Spanned::new(ast::Var { id: v.id }, v.span())),
            other => self.expr(other, soft)?,
        };
        Ok(ast::Call {
            expr: callee,
            args: self.args(&c.args, soft)?,
        })
    }

    fn opt<'a>(&self, e: &Option<Expr<'a>>, soft: bool, span: Span) -> Result<Expr<'a>, String> {
        match e {
            Some(e) => self.expr(e, soft),
            None => Ok(konst(Value::from(()), span)),
        }
    }

    fn expr<'a>(&self, e: &Expr<'a>, soft: bool) -> Result<Expr<'a>, String> {
        use ast::BinOpKind as B;
        let span = e.span();
        Ok(match e {
            Expr::Var(v) => Expr::Var(Spanned::new(ast::Var { id: v.id }, span)),
            Expr::Const(c) => konst(c.value.clone(), span),
            Expr::Slice(s) => call(
                "%slice",
                vec![
                    self.expr(&s.expr, soft)?,
                    self.opt(&s.start, soft, span)?,
                    self.opt(&s.stop, soft, span)?,
                    self.opt(&s.step, soft, span)?,
                ],
                span,
            ),
            Expr::UnaryOp(u) => match u.op {
                ast::UnaryOpKind::Not => Expr::UnaryOp(Spanned::new(
                    ast::UnaryOp {
                        op: ast::UnaryOpKind::Not,
                        expr: self.expr(&u.expr, soft)?,
                    },
                    span,
                )),
                ast::UnaryOpKind::Neg => call("%neg", vec![self.expr(&u.expr, soft)?], span),
            },
            Expr::BinOp(b) => {
                let (l, r) = (self.expr(&b.left, soft)?, self.expr(&b.right, soft)?);
                let cmp = |op: &str, l, r| {
                    call("%compare", vec![l, konst(Value::from(op), span), r], span)
                };
                match b.op {
                    B::ScAnd | B::ScOr => Expr::BinOp(Spanned::new(
                        ast::BinOp {
                            op: b.op,
                            left: l,
                            right: r,
                        },
                        span,
                    )),
                    B::Eq => cmp("eq", l, r),
                    B::Ne => cmp("ne", l, r),
                    B::Lt => cmp("lt", l, r),
                    B::Lte => cmp("le", l, r),
                    B::Gt => cmp("gt", l, r),
                    B::Gte => cmp("ge", l, r),
                    B::In => cmp("in", l, r),
                    B::Add => call("%add", vec![l, r], span),
                    B::Sub => call("%sub", vec![l, r], span),
                    B::Mul => call("%mul", vec![l, r], span),
                    B::Div => call("%div", vec![l, r], span),
                    B::FloorDiv => call("%floordiv", vec![l, r], span),
                    B::Rem => call("%mod", vec![l, r], span),
                    B::Pow => call("%pow", vec![l, r], span),
                    B::Concat => call("%concat", vec![l, r], span),
                }
            }
            Expr::Compare(c) => {
                let mut args = vec![self.expr(&c.expr, soft)?];
                for op in &c.ops {
                    use ast::CompareOpKind as C;
                    let name = match op.op {
                        C::Eq => "eq",
                        C::Ne => "ne",
                        C::Lt => "lt",
                        C::Lte => "le",
                        C::Gt => "gt",
                        C::Gte => "ge",
                        C::In => "in",
                        C::NotIn => "notin",
                    };
                    args.push(konst(Value::from(name), span));
                    args.push(self.expr(&op.expr, soft)?);
                }
                call("%compare", args, span)
            }
            Expr::IfExpr(i) => {
                let id = span.start_offset * 2;
                let true_expr = self.expr(&i.true_expr, true)?;
                // Jinja2's missing else is its plain Undefined even under StrictUndefined
                let false_expr = match &i.false_expr {
                    Some(f) => self.expr(f, true)?,
                    None => call("%lenient_undefined", Vec::new(), span),
                };
                Expr::IfExpr(Spanned::new(
                    ast::IfExpr {
                        test_expr: self.expr(&i.test_expr, true)?,
                        true_expr: self.marked(id, true_expr, span),
                        false_expr: Some(self.marked(id + 1, false_expr, span)),
                    },
                    span,
                ))
            }
            Expr::Filter(f) => {
                if !soft && !(self.check.filters)(f.name) {
                    return Err(format!("No filter named '{}'.", f.name));
                }
                Expr::Filter(Spanned::new(
                    ast::Filter {
                        name: f.name,
                        expr: f.expr.as_ref().map(|e| self.expr(e, soft)).transpose()?,
                        args: self.args(&f.args, soft)?,
                    },
                    span,
                ))
            }
            Expr::Test(t) => {
                if !soft && !(self.check.tests)(t.name) {
                    return Err(format!("No test named '{}'.", t.name));
                }
                Expr::Test(Spanned::new(
                    ast::Test {
                        name: t.name,
                        expr: self.expr(&t.expr, soft)?,
                        args: self.args(&t.args, soft)?,
                    },
                    span,
                ))
            }
            Expr::GetAttr(g) => call(
                "%getattr",
                vec![self.expr(&g.expr, soft)?, konst(Value::from(g.name), span)],
                span,
            ),
            Expr::GetItem(g) => call(
                "%getitem",
                vec![
                    self.expr(&g.expr, soft)?,
                    self.expr(&g.subscript_expr, soft)?,
                ],
                span,
            ),
            Expr::Call(c) => Expr::Call(Spanned::new(self.call_node(c, soft)?, span)),
            Expr::List(l) => call(
                "%list",
                l.items
                    .iter()
                    .map(|i| self.expr(i, soft))
                    .collect::<Result<_, _>>()?,
                span,
            ),
            Expr::Tuple(t) => call(
                "%tuple",
                t.items
                    .iter()
                    .map(|i| self.expr(i, soft))
                    .collect::<Result<_, _>>()?,
                span,
            ),
            Expr::Map(m) => {
                let mut args = Vec::with_capacity(m.keys.len() * 2);
                for (k, v) in m.keys.iter().zip(&m.values) {
                    args.push(self.expr(k, soft)?);
                    args.push(self.expr(v, soft)?);
                }
                call("%dict", args, span)
            }
        })
    }
}

/// ace3's `_extract_paths` over a parsed template.
pub fn paths(stmt: &Stmt<'_>) -> Vec<Vec<Segment>> {
    let mut raw: Vec<Vec<Segment>> = Vec::new();
    walk_stmt(stmt, &mut raw);
    // longest first, stably, so each kept chain is maximal
    raw.sort_by_key(|c| std::cmp::Reverse(c.len()));
    let mut kept: Vec<Vec<Segment>> = Vec::new();
    for chain in raw {
        if kept
            .iter()
            .any(|k| chain.len() < k.len() && k[..chain.len()] == chain[..])
        {
            continue;
        }
        if !kept.contains(&chain) {
            kept.push(chain);
        }
    }
    kept
}

/// `_node_to_chain`: a name with its attributes and constant subscripts, or nothing when any
/// part isn't static.
fn chain(e: &Expr<'_>) -> Option<Vec<Segment>> {
    let mut parts = Vec::new();
    let mut node = e;
    loop {
        match node {
            Expr::Var(v) => {
                parts.push(Segment::Name(v.id.to_owned()));
                break;
            }
            Expr::GetAttr(g) => {
                parts.push(Segment::Name(g.name.to_owned()));
                node = &g.expr;
            }
            Expr::GetItem(g) => {
                let Expr::Const(c) = &g.subscript_expr else {
                    return None;
                };
                let v = &c.value;
                if let Some(s) = v.as_str() {
                    parts.push(Segment::Name(s.to_owned()));
                } else if v.is_integer() {
                    parts.push(Segment::Index(i128::try_from(v.clone()).ok()?));
                } else if v.kind() == minijinja::value::ValueKind::Bool {
                    parts.push(Segment::Index(i128::from(v.is_true())));
                } else {
                    return None;
                }
                node = &g.expr;
            }
            _ => return None,
        }
    }
    parts.reverse();
    Some(parts)
}

fn walk_body(body: &[Stmt<'_>], out: &mut Vec<Vec<Segment>>) {
    for s in body {
        walk_stmt(s, out);
    }
}

/// Jinja2's `find_all` over the node each statement parses to there: a matching node before its
/// children, and the children in the order Jinja2's node declares its fields.
fn walk_stmt(stmt: &Stmt<'_>, out: &mut Vec<Vec<Segment>>) {
    match stmt {
        Stmt::Template(t) => walk_body(&t.children, out),
        Stmt::EmitExpr(e) => walk_expr(&e.expr, out),
        Stmt::EmitRaw(_) => {}
        // For(target, iter, body, else_, test)
        Stmt::ForLoop(f) => {
            walk_expr(&f.target, out);
            walk_expr(&f.iter, out);
            walk_body(&f.body, out);
            walk_body(&f.else_body, out);
            if let Some(test) = &f.filter_expr {
                walk_expr(test, out);
            }
        }
        // If(test, body, elif_, else_): an elif is a nested If, in the same order
        Stmt::IfCond(i) => {
            walk_expr(&i.expr, out);
            walk_body(&i.true_body, out);
            walk_body(&i.false_body, out);
        }
        // With(targets, values, body)
        Stmt::WithBlock(w) => {
            for (t, _) in &w.assignments {
                walk_expr(t, out);
            }
            for (_, v) in &w.assignments {
                walk_expr(v, out);
            }
            walk_body(&w.body, out);
        }
        // Assign(target, node); a namespace attribute target is an NSRef, which isn't a name
        Stmt::Set(s) => {
            walk_target(&s.target, out);
            walk_expr(&s.expr, out);
        }
        // AssignBlock(target, filter, body)
        Stmt::SetBlock(s) => {
            walk_target(&s.target, out);
            if let Some(f) = &s.filter {
                walk_expr(f, out);
            }
            walk_body(&s.body, out);
        }
        Stmt::AutoEscape(a) => {
            walk_expr(&a.enabled, out);
            walk_body(&a.body, out);
        }
        // FilterBlock(body, filter)
        Stmt::FilterBlock(f) => {
            walk_body(&f.body, out);
            walk_expr(&f.filter, out);
        }
        // Macro(name, args, defaults, body)
        Stmt::Macro(m) => walk_macro(m, out),
        // CallBlock(call, args, defaults, body)
        Stmt::CallBlock(c) => {
            walk_call(&c.call, out);
            walk_macro(&c.macro_decl, out);
        }
        Stmt::Do(d) => walk_call(&d.call, out),
        Stmt::Block(b) => walk_body(&b.body, out),
        Stmt::Extends(x) => walk_expr(&x.name, out),
        Stmt::Include(i) => walk_expr(&i.name, out),
        Stmt::Import(i) => walk_expr(&i.expr, out),
        Stmt::FromImport(i) => walk_expr(&i.expr, out),
    }
}

fn walk_target(e: &Expr<'_>, out: &mut Vec<Vec<Segment>>) {
    match e {
        Expr::GetAttr(_) => {}
        other => walk_expr(other, out),
    }
}

fn walk_macro(m: &ast::Macro<'_>, out: &mut Vec<Vec<Segment>>) {
    for a in &m.args {
        walk_expr(a, out);
    }
    for d in &m.defaults {
        walk_expr(d, out);
    }
    walk_body(&m.body, out);
}

/// Call(node, args, kwargs, dyn_args, dyn_kwargs)
fn walk_call(c: &ast::Call<'_>, out: &mut Vec<Vec<Segment>>) {
    walk_expr(&c.expr, out);
    walk_args(&c.args, out);
}

fn walk_args(args: &[CallArg<'_>], out: &mut Vec<Vec<Segment>>) {
    for a in args {
        if let CallArg::Pos(e) = a {
            walk_expr(e, out);
        }
    }
    for a in args {
        if let CallArg::Kwarg(_, e) = a {
            walk_expr(e, out);
        }
    }
    for a in args {
        if let CallArg::PosSplat(e) = a {
            walk_expr(e, out);
        }
    }
    for a in args {
        if let CallArg::KwargSplat(e) = a {
            walk_expr(e, out);
        }
    }
}

fn walk_expr(e: &Expr<'_>, out: &mut Vec<Vec<Segment>>) {
    if matches!(
        e,
        Expr::Var(_) | Expr::GetAttr(_) | Expr::GetItem(_) | Expr::Slice(_)
    ) {
        // a slice is Jinja2's Getitem with a Slice for its argument, so never a chain
        if let Some(c) = chain(e) {
            out.push(c);
        }
    }
    match e {
        Expr::Var(_) | Expr::Const(_) => {}
        Expr::Slice(s) => {
            walk_expr(&s.expr, out);
            for part in [&s.start, &s.stop, &s.step].into_iter().flatten() {
                walk_expr(part, out);
            }
        }
        Expr::UnaryOp(u) => walk_expr(&u.expr, out),
        Expr::BinOp(b) => {
            walk_expr(&b.left, out);
            walk_expr(&b.right, out);
        }
        Expr::Compare(c) => {
            walk_expr(&c.expr, out);
            for op in &c.ops {
                walk_expr(&op.expr, out);
            }
        }
        // CondExpr(test, expr1, expr2)
        Expr::IfExpr(i) => {
            walk_expr(&i.test_expr, out);
            walk_expr(&i.true_expr, out);
            if let Some(f) = &i.false_expr {
                walk_expr(f, out);
            }
        }
        Expr::Filter(f) => {
            if let Some(inner) = &f.expr {
                walk_expr(inner, out);
            }
            walk_args(&f.args, out);
        }
        Expr::Test(t) => {
            walk_expr(&t.expr, out);
            walk_args(&t.args, out);
        }
        Expr::GetAttr(g) => walk_expr(&g.expr, out),
        Expr::GetItem(g) => {
            walk_expr(&g.expr, out);
            walk_expr(&g.subscript_expr, out);
        }
        Expr::Call(c) => walk_call(c, out),
        Expr::List(l) => l.items.iter().for_each(|i| walk_expr(i, out)),
        Expr::Tuple(t) => t.items.iter().for_each(|i| walk_expr(i, out)),
        // Dict(items=[Pair(key, value)])
        Expr::Map(m) => {
            for (k, v) in m.keys.iter().zip(&m.values) {
                walk_expr(k, out);
                walk_expr(v, out);
            }
        }
    }
}
