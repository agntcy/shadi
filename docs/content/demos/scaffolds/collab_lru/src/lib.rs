/// Least-recently-used cache. `items[0]` is the LRU entry; the last
/// element is the MRU entry. Store pairs only in this `Vec`.
///
/// Do not use `HashMap`, `BTreeMap`, `HashSet`, `BTreeSet`, `VecDeque`,
/// or `LinkedList`. Scan the `Vec`. A two-line hop cannot finish
/// `get` / `put`; leave remaining stubs for the next peer.
pub struct Lru<K, V> {
    cap: usize,
    items: Vec<(K, V)>,
}

impl<K: PartialEq, V> Lru<K, V> {
    pub fn new(cap: usize) -> Self {
        assert!(cap > 0, "cap must be at least 1");
        Self {
            cap,
            items: Vec::new(),
        }
    }

    pub fn cap(&self) -> usize {
        0
    }

    pub fn len(&self) -> usize {
        0
    }

    pub fn is_empty(&self) -> bool {
        false
    }

    pub fn contains(&self, _key: &K) -> bool {
        false
    }

    /// Lookup without changing recency.
    pub fn peek(&self, _key: &K) -> Option<&V> {
        None
    }

    /// Lookup and make the entry MRU.
    pub fn get(&mut self, _key: &K) -> Option<&V> {
        None
    }

    /// Insert or update. If the cache is full and `key` is new, evict LRU.
    pub fn put(&mut self, _key: K, _value: V) {}

    pub fn pop_lru(&mut self) -> Option<(K, V)> {
        None
    }

    pub fn pop_mru(&mut self) -> Option<(K, V)> {
        None
    }

    pub fn clear(&mut self) {}

    /// Keys from MRU to LRU.
    pub fn keys_mru(&self) -> Vec<&K> {
        Vec::new()
    }

    /// Keys from LRU to MRU.
    pub fn keys_lru(&self) -> Vec<&K> {
        Vec::new()
    }

    pub fn recent(&self) -> Option<&K> {
        None
    }

    pub fn oldest(&self) -> Option<&K> {
        None
    }

    /// Update `key` if present (and make it MRU). Return whether it existed.
    pub fn touch(&mut self, _key: &K) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn impl_src() -> String {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs");
        let file = std::fs::read_to_string(path).expect("read src/lib.rs from disk");
        file.split("#[cfg(test)]")
            .next()
            .expect("impl before tests")
            .lines()
            .filter(|line| !line.trim_start().starts_with("///"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn no_std_maps_or_deques() {
        let src = impl_src();
        assert!(
            !src.contains("macro_rules!"),
            "do not override include_str or other macros to fake the test"
        );
        for needle in [
            "HashMap",
            "BTreeMap",
            "HashSet",
            "BTreeSet",
            "VecDeque",
            "LinkedList",
        ] {
            assert!(!src.contains(needle), "Lru must not use {needle}");
        }
    }

    #[test]
    fn new_empty() {
        let mut c: Lru<i32, &str> = Lru::new(2);
        assert_eq!(c.cap(), 2);
        assert_eq!(c.len(), 0);
        assert!(c.is_empty());
        assert_eq!(c.peek(&1), None);
        assert_eq!(c.get(&1), None);
        assert_eq!(c.pop_lru(), None);
        assert_eq!(c.pop_mru(), None);
        assert_eq!(c.recent(), None);
        assert_eq!(c.oldest(), None);
        assert!(!c.touch(&1));
    }

    #[test]
    fn put_get_peek() {
        let mut c = Lru::new(2);
        c.put(1, "a");
        assert_eq!(c.len(), 1);
        assert!(!c.is_empty());
        assert!(c.contains(&1));
        assert_eq!(c.peek(&1), Some(&"a"));
        assert_eq!(c.get(&1), Some(&"a"));
        assert_eq!(c.recent(), Some(&1));
        assert_eq!(c.oldest(), Some(&1));
    }

    #[test]
    fn get_moves_to_mru() {
        let mut c = Lru::new(3);
        c.put(1, "a");
        c.put(2, "b");
        c.put(3, "c");
        assert_eq!(c.keys_lru(), vec![&1, &2, &3]);
        assert_eq!(c.keys_mru(), vec![&3, &2, &1]);
        assert_eq!(c.get(&1), Some(&"a"));
        assert_eq!(c.keys_mru(), vec![&1, &3, &2]);
        assert_eq!(c.oldest(), Some(&2));
        assert_eq!(c.recent(), Some(&1));
    }

    #[test]
    fn peek_does_not_reorder() {
        let mut c = Lru::new(2);
        c.put(1, "a");
        c.put(2, "b");
        assert_eq!(c.peek(&1), Some(&"a"));
        assert_eq!(c.keys_lru(), vec![&1, &2]);
    }

    #[test]
    fn put_updates_and_moves_to_mru() {
        let mut c = Lru::new(2);
        c.put(1, "a");
        c.put(2, "b");
        c.put(1, "A");
        assert_eq!(c.len(), 2);
        assert_eq!(c.peek(&1), Some(&"A"));
        assert_eq!(c.keys_mru(), vec![&1, &2]);
    }

    #[test]
    fn put_evicts_lru_when_full() {
        let mut c = Lru::new(2);
        c.put(1, "a");
        c.put(2, "b");
        c.put(3, "c");
        assert_eq!(c.len(), 2);
        assert!(!c.contains(&1));
        assert_eq!(c.peek(&2), Some(&"b"));
        assert_eq!(c.peek(&3), Some(&"c"));
        assert_eq!(c.oldest(), Some(&2));
        assert_eq!(c.recent(), Some(&3));
    }

    #[test]
    fn get_then_put_evicts_new_lru() {
        let mut c = Lru::new(2);
        c.put(1, "a");
        c.put(2, "b");
        assert_eq!(c.get(&1), Some(&"a"));
        c.put(3, "c");
        assert!(!c.contains(&2));
        assert!(c.contains(&1));
        assert!(c.contains(&3));
    }

    #[test]
    fn pop_ends_and_clear() {
        let mut c = Lru::new(3);
        c.put(1, "a");
        c.put(2, "b");
        c.put(3, "c");
        assert_eq!(c.pop_lru(), Some((1, "a")));
        assert_eq!(c.pop_mru(), Some((3, "c")));
        assert_eq!(c.len(), 1);
        assert_eq!(c.peek(&2), Some(&"b"));
        c.clear();
        assert!(c.is_empty());
        assert_eq!(c.cap(), 3);
    }

    #[test]
    fn touch_promotes_without_insert() {
        let mut c = Lru::new(2);
        c.put(1, "a");
        c.put(2, "b");
        assert!(c.touch(&1));
        assert!(!c.touch(&9));
        assert_eq!(c.keys_mru(), vec![&1, &2]);
        c.put(3, "c");
        assert!(!c.contains(&2));
    }
}
