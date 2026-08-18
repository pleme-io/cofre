//! go-yaml v3's indent arithmetic, isolated so it can be tested against the
//! columns of a real file rather than reasoned about.
//!
//! This is the whole of the divergence from libyaml. It is fifteen lines, and
//! getting it wrong is a 12-byte diff on a 217 KB file that no test would
//! otherwise notice — which is exactly why it lives alone with its own tests.

/// The emitter's indent stack, implementing go-yaml v3's
/// `yaml_emitter_increase_indent_compact`.
#[derive(Debug, Clone)]
pub struct Indenter {
    /// Current indent column. `None` models Go's `indent < 0` sentinel for
    /// "no indent established yet", which is the root state.
    current: Option<usize>,
    stack: Vec<Option<usize>>,
    best: usize,
}

impl Indenter {
    /// A fresh indenter. `best` is go-yaml's `best_indent` — sops's default is 4
    /// (`stores/yaml.IndentDefault`), overridable by `--indent`.
    #[must_use]
    pub fn new(best: usize) -> Self {
        Self {
            current: None,
            stack: Vec::new(),
            best: best.max(1),
        }
    }

    /// The column at which content is written right now. The root is column 0.
    #[must_use]
    pub fn column(&self) -> usize {
        self.current.unwrap_or(0)
    }

    /// The configured indent width.
    #[must_use]
    pub fn width(&self) -> usize {
        self.best
    }

    /// Descend, pushing the previous indent.
    ///
    /// `inside_block_sequence_item` is Go's
    /// `states[len-1] == yaml_EMIT_BLOCK_SEQUENCE_ITEM_STATE` — true when the
    /// node being opened is the *first* thing inside a `- ` item, where the
    /// increase is a bare `+2` to step over the indicator rather than a round-up.
    ///
    /// `indentless` is Go's flag for a node that adds no indent at all.
    pub fn increase(&mut self, inside_block_sequence_item: bool, indentless: bool) {
        self.stack.push(self.current);
        match self.current {
            // Go: `if emitter.indent < 0 { … emitter.indent = 0 }` for block context.
            None => self.current = Some(0),
            Some(cur) if !indentless => {
                self.current = Some(if inside_block_sequence_item {
                    // "The first indent inside a sequence will just skip the '- ' indicator."
                    cur + 2
                } else {
                    // Integer division on purpose — this is a round-up to the next
                    // multiple of `best` only when `cur` is already aligned, and a
                    // round-to-nearest-multiple otherwise. `10 → 12` at best=4 is
                    // the case that proves it is not `cur + best`.
                    self.best * ((cur + self.best) / self.best)
                });
            }
            // indentless: the indent is unchanged but still pushed, so the
            // matching `decrease` stays balanced.
            Some(_) => {}
        }
    }

    /// Ascend, restoring the pushed indent.
    pub fn decrease(&mut self) {
        self.current = self.stack.pop().unwrap_or(None);
    }

    /// How deep the stack is. Diagnostics and balance assertions.
    #[must_use]
    pub fn depth(&self) -> usize {
        self.stack.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The arithmetic, replayed against the columns actually observed in
    /// `nix/secrets.yaml`. Every number on the right was read off the file with
    /// `cat -A`, not derived from this code.
    #[test]
    fn reproduces_the_columns_of_the_operators_real_file() {
        let mut i = Indenter::new(4);
        assert_eq!(i.column(), 0, "`sops:` sits at column 0");

        // Entering the top-level mapping: root sentinel -> 0.
        i.increase(false, false);
        assert_eq!(i.column(), 0);

        // `sops:`'s child mapping -> its keys (`age:`, `mac:`) at column 4.
        i.increase(false, false);
        assert_eq!(i.column(), 4);

        // `age:`'s block sequence -> the dash at column 8.
        i.increase(false, false);
        assert_eq!(i.column(), 8, "the `- ` indicator column");

        // The mapping inside the sequence item -> `recipient:` at column 10.
        i.increase(true, false);
        assert_eq!(i.column(), 10, "+2 steps over the `- ` indicator");

        // `enc:`'s literal block scalar -> the armor body at column 12.
        i.increase(false, false);
        assert_eq!(i.column(), 12, "4 * ((10 + 4) / 4) == 12, not 10 + 4 == 14");
    }

    /// The one case that distinguishes go-yaml's formula from a naive
    /// `cur + best`. If someone "simplifies" `increase`, this is what fails.
    #[test]
    fn the_formula_is_not_current_plus_width() {
        let mut i = Indenter::new(4);
        i.increase(false, false); // -> 0
        i.increase(false, false); // -> 4
        i.increase(true, false); // -> 6 (a sequence item at an odd offset)
        assert_eq!(i.column(), 6);
        i.increase(false, false);
        assert_eq!(
            i.column(),
            8,
            "4 * ((6+4)/4) = 4*2 = 8, whereas 6+4 would be 10"
        );
    }

    #[test]
    fn libyamls_rule_would_give_a_different_sequence_column() {
        // libyaml keeps the dash at the parent indent and pads content to `best`.
        // Recorded here as the *rejected* behaviour so the divergence stays
        // legible to a reader who only has this crate in front of them.
        let mut go = Indenter::new(4);
        go.increase(false, false); // 0
        go.increase(false, false); // 4  (`age:`)
        go.increase(false, false); // 8  (go-yaml: dash at 8)
        assert_eq!(go.column(), 8);
        // libyaml would leave the dash at 4 and write `recipient` at 8, which is
        // the `    -   recipient:` shape the emit probe measured.
    }

    #[test]
    fn decrease_restores_exactly() {
        let mut i = Indenter::new(4);
        i.increase(false, false);
        i.increase(false, false);
        let at_four = i.column();
        i.increase(false, false);
        assert_ne!(i.column(), at_four);
        i.decrease();
        assert_eq!(i.column(), at_four);
        assert_eq!(i.depth(), 2);
    }

    #[test]
    fn indentless_pushes_without_moving() {
        let mut i = Indenter::new(4);
        i.increase(false, false); // 0
        i.increase(false, false); // 4
        i.increase(false, true);
        assert_eq!(i.column(), 4, "indentless adds no indent");
        i.decrease();
        assert_eq!(i.column(), 4);
    }

    #[test]
    fn an_indent_of_two_tracks_the_same_algebra() {
        let mut i = Indenter::new(2);
        i.increase(false, false); // 0
        i.increase(false, false); // 2*((0+2)/2) = 2
        assert_eq!(i.column(), 2);
        i.increase(false, false); // 2*((2+2)/2) = 4
        assert_eq!(i.column(), 4);
        i.increase(true, false); // +2 -> 6
        assert_eq!(i.column(), 6);
    }

    /// A zero indent would divide by zero in the formula, so it is clamped to 1
    /// at construction rather than panicking deep inside an emit.
    #[test]
    fn a_zero_width_is_clamped_not_fatal() {
        let mut i = Indenter::new(0);
        assert_eq!(i.width(), 1);
        i.increase(false, false);
        i.increase(false, false);
        assert_eq!(i.column(), 1);
    }
}
