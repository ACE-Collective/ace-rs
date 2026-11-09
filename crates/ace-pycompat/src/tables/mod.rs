//! Tables generated from ace3's Python by the scripts in `tables/` (`tables/run` regenerates them).

// The generated files are left as the generators write them, so regenerating changes nothing.
#[rustfmt::skip]
pub(crate) mod entities;
#[rustfmt::skip]
pub(crate) mod idnadata;
#[rustfmt::skip]
pub(crate) mod regex_classes;
#[rustfmt::skip]
pub(crate) mod stringprep;
#[rustfmt::skip]
pub(crate) mod unicode;

/// Whether `cp` is in one of `table`'s sorted, disjoint, inclusive ranges.
#[inline]
pub(crate) fn in_ranges(table: &[(u32, u32)], cp: u32) -> bool {
    let i = table.partition_point(|&(_, end)| end < cp);
    i < table.len() && table[i].0 <= cp
}

/// The value of the run `cp` falls in. The first run starts at 0.
#[inline]
pub(crate) fn run_value(table: &[(u32, u8)], cp: u32) -> u8 {
    let i = table.partition_point(|&(start, _)| start <= cp);
    table[i - 1].1
}

/// `cp`'s entry in a table sorted by code point.
#[inline]
pub(crate) fn lookup<T: Copy>(table: &[(u32, T)], cp: u32) -> Option<T> {
    table
        .binary_search_by_key(&cp, |&(key, _)| key)
        .ok()
        .map(|i| table[i].1)
}
