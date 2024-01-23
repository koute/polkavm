use std::collections::HashSet;
use std::sync::Arc;

#[derive(Default)]
pub struct StringCache(HashSet<Arc<str>>);

impl StringCache {
    pub fn dedup(&mut self, string: &str) -> Arc<str> {
        if let Some(string) = self.0.get(string) {
            return Arc::clone(string);
        }

        let string: Arc<str> = string.into();
        self.0.insert(Arc::clone(&string));
        string
    }
}
