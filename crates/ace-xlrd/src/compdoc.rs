//! compdoc.py: the OLE2 container checks and the workbook stream's extraction.

use crate::py::{
    R, ascii_str, err, i32_at, need, repr_bytes, repr_str, slice, span, u8_at, u16_at, utf16le,
};

const SIGNATURE: &[u8] = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1";
const EOCSID: i32 = -2;
const FREESID: i32 = -1;
const MSATSID: i32 = -4;
/// _get_stream on the short stream has no `seen` check, so a cycle in the SSAT never ends in
/// Python. This bounds the walk when `expired` never fires.
const MAX_SHORT_WALK: u64 = 1 << 28;
/// Python's default recursion limit less the frames above _build_family_tree when the wrapper is
/// called from a script. Cycles always hit it; only a real chain that long depends on the number.
const FAMILY_TREE_DEPTH: u32 = 992;
const MAX_CHILDREN: u64 = 1 << 24;

fn compdoc_err(message: impl Into<String>) -> crate::XlError {
    err("CompDocError", message)
}

struct DirNode {
    did: i64,
    etype: u8,
    left: i32,
    right: i32,
    root: i32,
    first_sid: i32,
    tot_size: i32,
    name: String,
    children: Vec<i32>,
    parent: i64,
}

impl DirNode {
    fn new(did: i64, dent: &[u8]) -> R<DirNode> {
        let a = need(slice(dent, 64, 80), 16)?;
        let cbufsize = u16_at(a, 0) as i64;
        let b = need(slice(dent, 116, 124), 8)?;
        let name = if cbufsize == 0 {
            String::new()
        } else {
            utf16le(slice(dent, 0, cbufsize - 2))?
        };
        need(slice(dent, 100, 116), 16)?;
        Ok(DirNode {
            did,
            etype: u8_at(a, 2),
            left: i32_at(a, 4),
            right: i32_at(a, 8),
            root: i32_at(a, 12),
            first_sid: i32_at(b, 0),
            tot_size: i32_at(b, 4),
            name,
            children: Vec::new(),
            parent: -1,
        })
    }

    fn dump(&self, log: &mut String) {
        let kids: Vec<String> = self.children.iter().map(i32::to_string).collect();
        log.push_str(&format!(
            "DID={} name={} etype={} DIDs(left={} right={} root={} parent={} kids=[{}]) first_SID={} tot_size={}\n",
            self.did,
            ascii_str(&self.name),
            self.etype,
            self.left,
            self.right,
            self.root,
            self.parent,
            kids.join(", "),
            self.first_sid,
            self.tot_size
        ));
    }
}

/// What locate_named_stream returned: a stream inside the file, or bytes that were joined.
pub(crate) enum Located {
    NotFound,
    InFile { base: i64 },
    Joined(Vec<u8>),
}

pub(crate) struct CompDoc<'a> {
    mem: &'a [u8],
    sec_size: i64,
    short_sec_size: i64,
    min_size_std_stream: i32,
    mem_data_len: i64,
    seen: Vec<u8>,
    sat: Vec<i32>,
    ssat: Vec<i32>,
    /// None is `self.SSCS = ""`, a str: joining a slice of it is a TypeError.
    sscs: Option<Vec<u8>>,
    dirlist: Vec<DirNode>,
}

struct Walk<'x> {
    expired: &'x dyn Fn() -> bool,
    children: u64,
}

impl<'a> CompDoc<'a> {
    pub(crate) fn new(mem: &'a [u8], log: &mut String, expired: &dyn Fn() -> bool) -> R<Self> {
        if slice(mem, 0, 8) != SIGNATURE {
            return Err(compdoc_err("Not an OLE2 compound document"));
        }
        let marker = slice(mem, 28, 30);
        if marker != b"\xFE\xFF" {
            return Err(compdoc_err(format!(
                "Expected \"little-endian\" marker, found {}",
                repr_bytes(marker)
            )));
        }
        need(slice(mem, 24, 28), 4)?;
        let sizes = need(slice(mem, 30, 34), 4)?;
        let mut ssz = u16_at(sizes, 0) as u32;
        let mut sssz = u16_at(sizes, 2) as u32;
        if ssz > 20 {
            log.push_str(&format!(
                "WARNING: sector size (2**{ssz}) is preposterous; assuming 512 and continuing ...\n"
            ));
            ssz = 9;
        }
        if sssz > ssz {
            log.push_str(&format!(
                "WARNING: short stream sector size (2**{sssz}) is preposterous; assuming 64 and continuing ...\n"
            ));
            sssz = 6;
        }
        let sec_size = 1i64 << ssz;
        let short_sec_size = 1i64 << sssz;
        if sec_size != 512 || short_sec_size != 64 {
            log.push_str(&format!(
                "@@@@ sec_size={sec_size} short_sec_size={short_sec_size}\n"
            ));
        }
        let hdr = need(slice(mem, 44, 76), 32)?;
        let dir_first_sec_sid = i32_at(hdr, 4);
        let min_size_std_stream = i32_at(hdr, 12);
        let ssat_first_sec_sid = i32_at(hdr, 16);
        let ssat_tot_secs = i32_at(hdr, 20);
        let msatx_first_sec_sid = i32_at(hdr, 24);
        let msatx_tot_secs = i32_at(hdr, 28);
        let mem_data_len = mem.len() as i64 - 512;
        let mut mem_data_secs = mem_data_len.div_euclid(sec_size);
        if mem_data_len.rem_euclid(sec_size) != 0 {
            mem_data_secs += 1;
            log.push_str(&format!(
                "WARNING *** file size ({}) not 512 + multiple of sector size ({sec_size})\n",
                mem.len()
            ));
        }
        let mut seen = vec![0u8; mem_data_secs.max(0) as usize];
        let nent = sec_size / 4;
        let msat_head = need(slice(mem, 76, 512), 436)?;
        let mut msat = ints(msat_head);
        if nent == 0 || nent == 1 {
            return Err(err("ZeroDivisionError", "division by zero"));
        }
        if !(msatx_tot_secs == 0 && matches!(msatx_first_sec_sid, EOCSID | FREESID | 0)) {
            let mut sid = msatx_first_sec_sid;
            while !matches!(sid, EOCSID | FREESID | MSATSID) {
                if i64::from(sid) >= mem_data_secs {
                    return Err(compdoc_err(format!(
                        "MSAT extension: accessing sector {sid} but only {mem_data_secs} in file"
                    )));
                }
                if sid < 0 {
                    return Err(compdoc_err(format!(
                        "MSAT extension: invalid sector id: {sid}"
                    )));
                }
                let s = seen.get(sid as usize).copied().unwrap_or(0);
                if s != 0 {
                    return Err(compdoc_err(format!("MSAT corruption: seen[{sid}] == {s}")));
                }
                if let Some(v) = seen.get_mut(sid as usize) {
                    *v = 1;
                }
                let offset = 512 + sec_size * i64::from(sid);
                let sect = need(span(mem, offset, sec_size), (nent * 4) as usize)?;
                msat.extend(ints(sect));
                sid = msat.pop().unwrap_or(FREESID);
            }
        }
        let mut sat = Vec::new();
        let mut trunc_warned = false;
        for &msid in &msat {
            if msid == FREESID || msid == EOCSID {
                continue;
            }
            if i64::from(msid) >= mem_data_secs {
                if !trunc_warned {
                    log.push_str("WARNING *** File is truncated, or OLE2 MSAT is corrupt!!\n");
                    log.push_str(&format!(
                        "INFO: Trying to access sector {msid} but only {mem_data_secs} available\n"
                    ));
                    trunc_warned = true;
                }
                continue;
            }
            if msid < -2 {
                return Err(compdoc_err(format!("MSAT: invalid sector id: {msid}")));
            }
            let s = seen.get(msid as usize).copied().unwrap_or(0);
            if s != 0 {
                return Err(compdoc_err(format!(
                    "MSAT extension corruption: seen[{msid}] == {s}"
                )));
            }
            if let Some(v) = seen.get_mut(msid as usize) {
                *v = 2;
            }
            let offset = 512 + sec_size * i64::from(msid);
            sat.extend(ints(need(
                span(mem, offset, sec_size),
                (nent * 4) as usize,
            )?));
        }
        let mut doc = CompDoc {
            mem,
            sec_size,
            short_sec_size,
            min_size_std_stream,
            mem_data_len,
            seen,
            sat,
            ssat: Vec::new(),
            sscs: None,
            dirlist: Vec::new(),
        };
        let dbytes = doc.get_stream_file(dir_first_sec_sid, None, "directory", 3, log)?;
        let mut pos = 0i64;
        let mut did = 0i64;
        while pos < dbytes.len() as i64 {
            doc.dirlist
                .push(DirNode::new(did, span(&dbytes, pos, 128))?);
            did += 1;
            pos += 128;
        }
        let root = doc
            .dirlist
            .first()
            .map(|d| d.root)
            .ok_or_else(crate::py::list_index_error)?;
        let mut walk = Walk {
            expired,
            children: 0,
        };
        doc.build_family_tree(0, root, 0, &mut walk)?;
        let (etype, first_sid, tot_size) = doc
            .dirlist
            .first()
            .map(|d| (d.etype, d.first_sid, d.tot_size))
            .ok_or_else(crate::py::list_index_error)?;
        if etype != 5 {
            return Err(crate::py::assertion());
        }
        if first_sid >= 0 && tot_size != 0 {
            let s = doc.get_stream_file(first_sid, Some(i64::from(tot_size)), "SSCS", 4, log)?;
            doc.sscs = Some(s);
        }
        if ssat_tot_secs > 0 && tot_size == 0 {
            log.push_str(
                "WARNING *** OLE2 inconsistency: SSCS size is 0 but SSAT size is non-zero\n",
            );
        }
        if tot_size > 0 {
            let mut sid = ssat_first_sec_sid;
            let mut nsecs = ssat_tot_secs;
            while sid >= 0 && nsecs > 0 {
                let s = doc.seen_at(i64::from(sid))?;
                if s != 0 {
                    return Err(compdoc_err(format!("SSAT corruption: seen[{sid}] == {s}")));
                }
                doc.set_seen(i64::from(sid), 5);
                nsecs -= 1;
                let start = 512 + i64::from(sid) * sec_size;
                let news = ints(need(span(mem, start, sec_size), (nent * 4) as usize)?);
                doc.ssat.extend(news);
                sid = doc
                    .sat
                    .get(sid as usize)
                    .copied()
                    .ok_or_else(crate::py::list_index_error)?;
            }
            if !(nsecs == 0 && sid == EOCSID) {
                return Err(crate::py::assertion());
            }
        }
        Ok(doc)
    }

    fn seen_at(&self, s: i64) -> R<u8> {
        self.seen
            .get(s as usize)
            .copied()
            .ok_or_else(|| err("IndexError", "array index out of range"))
    }

    fn set_seen(&mut self, s: i64, v: u8) {
        if let Some(x) = self.seen.get_mut(s as usize) {
            *x = v;
        }
    }

    fn build_family_tree(&mut self, parent: i32, child: i32, depth: u32, walk: &mut Walk) -> R<()> {
        if depth >= FAMILY_TREE_DEPTH {
            return Err(err("RecursionError", "maximum recursion depth exceeded"));
        }
        if child < 0 {
            return Ok(());
        }
        if (walk.expired)() {
            return Err(err(
                "PassTimeout",
                "timed out in compound document directory",
            ));
        }
        let (left, right, root, etype) = self
            .dirlist
            .get(child as usize)
            .map(|d| (d.left, d.right, d.root, d.etype))
            .ok_or_else(crate::py::list_index_error)?;
        self.build_family_tree(parent, left, depth + 1, walk)?;
        walk.children += 1;
        if walk.children > MAX_CHILDREN {
            return Err(crate::py::memory_error());
        }
        if let Some(p) = self.dirlist.get_mut(parent as usize) {
            p.children.push(child);
        }
        if let Some(c) = self.dirlist.get_mut(child as usize) {
            c.parent = i64::from(parent);
        }
        self.build_family_tree(parent, right, depth + 1, walk)?;
        if etype == 1 {
            self.build_family_tree(child, root, depth + 1, walk)?;
        }
        Ok(())
    }

    /// _get_stream over the file itself, always with a seen_id.
    fn get_stream_file(
        &mut self,
        start_sid: i32,
        size: Option<i64>,
        name: &str,
        seen_id: u8,
        log: &mut String,
    ) -> R<Vec<u8>> {
        let mut sectors = Vec::new();
        let mut s = start_sid;
        let mut todo = size.unwrap_or(0);
        while s >= 0 {
            let cur = self.seen_at(i64::from(s))?;
            if cur != 0 {
                return Err(compdoc_err(format!(
                    "{name} corruption: seen[{s}] == {cur}"
                )));
            }
            self.set_seen(i64::from(s), seen_id);
            let start_pos = 512 + i64::from(s) * self.sec_size;
            let grab = if size.is_some() {
                let g = self.sec_size.min(todo);
                todo -= g;
                g
            } else {
                self.sec_size
            };
            sectors.extend_from_slice(span(self.mem, start_pos, grab));
            s = self.sat.get(s as usize).copied().ok_or_else(|| {
                compdoc_err(format!(
                    "OLE2 stream {}: sector allocation table invalid entry ({s})",
                    repr_str(name)
                ))
            })?;
        }
        if s != EOCSID {
            return Err(crate::py::assertion());
        }
        if let Some(sz) = size
            && todo != 0
        {
            log.push_str(&format!(
                "WARNING *** OLE2 stream {}: expected size {sz}, actual size {}\n",
                ascii_str(name),
                sz - todo
            ));
        }
        Ok(sectors)
    }

    /// _get_stream over the short stream: no seen check, and SSCS may be the empty str.
    fn get_stream_short(
        &mut self,
        start_sid: i32,
        size: i64,
        name: &str,
        log: &mut String,
        expired: &dyn Fn() -> bool,
    ) -> R<Vec<u8>> {
        let mut out = Vec::new();
        let mut any_sector = false;
        let mut s = start_sid;
        let mut todo = size;
        let mut walked = 0u64;
        let empty: &[u8] = &[];
        let sscs = self.sscs.as_deref().unwrap_or(empty);
        while s >= 0 {
            walked += 1;
            if walked.is_multiple_of(4096) && expired() {
                return Err(err("PassTimeout", "timed out reading the short stream"));
            }
            if walked > MAX_SHORT_WALK {
                return Err(crate::py::memory_error());
            }
            let start_pos = i64::from(s) * self.short_sec_size;
            let grab = self.short_sec_size.min(todo);
            todo -= grab;
            out.extend_from_slice(span(sscs, start_pos, grab));
            any_sector = true;
            s = self.ssat.get(s as usize).copied().ok_or_else(|| {
                compdoc_err(format!(
                    "OLE2 stream {}: sector allocation table invalid entry ({s})",
                    repr_str(name)
                ))
            })?;
        }
        if s != EOCSID {
            return Err(crate::py::assertion());
        }
        if todo != 0 {
            log.push_str(&format!(
                "WARNING *** OLE2 stream {}: expected size {size}, actual size {}\n",
                ascii_str(name),
                size - todo
            ));
        }
        if self.sscs.is_none() && any_sector {
            return Err(err(
                "TypeError",
                "sequence item 0: expected a bytes-like object, str found",
            ));
        }
        Ok(out)
    }

    fn dir_search(&self, head: &str, log: &mut String) -> R<Option<usize>> {
        let want = head.to_lowercase();
        let Some(root) = self.dirlist.first() else {
            return Ok(None);
        };
        for &child in &root.children {
            let idx = child as usize;
            let Some(d) = self.dirlist.get(idx) else {
                continue;
            };
            if d.name.to_lowercase() == want {
                if d.etype == 2 {
                    return Ok(Some(idx));
                }
                if d.etype == 1 {
                    return Err(compdoc_err("Requested component is a 'storage'"));
                }
                d.dump(log);
                return Err(compdoc_err("Requested stream is not a 'user stream'"));
            }
        }
        Ok(None)
    }

    pub(crate) fn locate_named_stream(
        &mut self,
        qname: &str,
        log: &mut String,
        expired: &dyn Fn() -> bool,
    ) -> R<Located> {
        let Some(idx) = self.dir_search(qname, log)? else {
            return Ok(Located::NotFound);
        };
        let (did, first_sid, tot_size) = self
            .dirlist
            .get(idx)
            .map(|d| (d.did, d.first_sid, i64::from(d.tot_size)))
            .ok_or_else(crate::py::list_index_error)?;
        if tot_size > self.mem_data_len {
            return Err(compdoc_err(format!(
                "{} stream length ({tot_size} bytes) > file data size ({} bytes)",
                repr_str(qname),
                self.mem_data_len
            )));
        }
        if tot_size >= i64::from(self.min_size_std_stream) {
            self.locate_stream(first_sid, tot_size, qname, did + 6, log)
        } else {
            let name = format!("{qname} (from SSCS)");
            let v = self.get_stream_short(first_sid, tot_size, &name, log, expired)?;
            Ok(Located::Joined(v))
        }
    }

    fn locate_stream(
        &mut self,
        start_sid: i32,
        expected: i64,
        qname: &str,
        seen_id: i64,
        log: &mut String,
    ) -> R<Located> {
        let mut s = start_sid;
        if s < 0 {
            return Err(compdoc_err(format!(
                "_locate_stream: start_sid ({start_sid}) is -ve"
            )));
        }
        let mut p = -99i64;
        let mut start_pos = -9999i64;
        let mut end_pos = -8888i64;
        let mut slices: Vec<(i64, i64)> = Vec::new();
        let mut tot_found = 0i64;
        let sec_size = self.sec_size;
        let found_limit = (expected + sec_size - 1).div_euclid(sec_size);
        while s >= 0 {
            let cur = self.seen_at(i64::from(s))?;
            if cur != 0 {
                log.push_str(&format!("_locate_stream({qname}): seen\n"));
                dump_list(&self.seen, 20, log);
                return Err(compdoc_err(format!(
                    "{qname} corruption: seen[{s}] == {cur}"
                )));
            }
            if seen_id > 255 {
                return Err(err(
                    "OverflowError",
                    "unsigned byte integer is greater than maximum",
                ));
            }
            self.set_seen(i64::from(s), seen_id as u8);
            tot_found += 1;
            if tot_found > found_limit {
                return Err(compdoc_err(format!(
                    "{qname}: size exceeds expected {} bytes; corrupt?",
                    found_limit * sec_size
                )));
            }
            if i64::from(s) == p + 1 {
                end_pos += sec_size;
            } else {
                if p >= 0 {
                    slices.push((start_pos, end_pos));
                }
                start_pos = 512 + i64::from(s) * sec_size;
                end_pos = start_pos + sec_size;
            }
            p = i64::from(s);
            s = self
                .sat
                .get(s as usize)
                .copied()
                .ok_or_else(crate::py::list_index_error)?;
        }
        if s != EOCSID || tot_found != found_limit {
            return Err(crate::py::assertion());
        }
        if slices.is_empty() {
            return Ok(Located::InFile { base: start_pos });
        }
        slices.push((start_pos, end_pos));
        let mut out = Vec::new();
        for (a, b) in slices {
            out.extend_from_slice(slice(self.mem, a, b));
        }
        Ok(Located::Joined(out))
    }
}

fn ints(d: &[u8]) -> Vec<i32> {
    (0..d.len() / 4).map(|i| i32_at(d, i * 4)).collect()
}

/// compdoc.dump_list.
fn dump_list(alist: &[u8], stride: usize, log: &mut String) {
    let line = |log: &mut String, dpos: usize, equal: bool| {
        log.push_str(&format!("{dpos:5}{} ", if equal { '=' } else { ' ' }));
        let end = (dpos + stride).min(alist.len());
        for v in alist.get(dpos..end).unwrap_or(&[]) {
            log.push_str(&format!("{v} "));
        }
        log.push('\n');
    };
    let chunk = |pos: usize| {
        let end = (pos + stride).min(alist.len());
        alist.get(pos..end).unwrap_or(&[])
    };
    let mut oldpos: Option<usize> = None;
    let mut last: Option<usize> = None;
    let mut pos = 0;
    while pos < alist.len() {
        last = Some(pos);
        match oldpos {
            None => {
                line(log, pos, false);
                oldpos = Some(pos);
            }
            Some(old) if chunk(pos) != chunk(old) => {
                if pos - old > stride {
                    line(log, pos - stride, true);
                }
                line(log, pos, false);
                oldpos = Some(pos);
            }
            Some(_) => {}
        }
        pos += stride;
    }
    if let (Some(old), Some(l)) = (oldpos, last)
        && l != old
    {
        line(log, l, true);
    }
}
