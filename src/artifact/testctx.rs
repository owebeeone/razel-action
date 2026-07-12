    use razel_core::{Key, NodeKey, NodeValue, Value};
    use razel_engine_api::{Demand, DemandContext};
    use std::collections::HashMap;
    use std::sync::Arc;

    /// A map-backed `DemandContext` for node-function unit tests: serves the values it was given, reports
    /// `Missing` otherwise, and RECORDS every requested key (so tests can assert the demand edges exist).
    pub(crate) struct MapCtx {
        served: HashMap<NodeKey, NodeValue>,
        pub(crate) requested: Vec<NodeKey>,
    }
    impl MapCtx {
        pub(crate) fn new() -> Self {
            Self { served: HashMap::new(), requested: Vec::new() }
        }
        pub(crate) fn serve<K: Key, V: Value>(mut self, k: &K, v: V) -> Self {
            self.served.insert(NodeKey::from_key(k), Arc::new(v));
            self
        }
    }
    impl DemandContext for MapCtx {
        fn request(&mut self, key: &NodeKey) -> Demand {
            self.requested.push(key.clone());
            match self.served.get(key) {
                Some(v) => Demand::Ready(v.clone()),
                None => Demand::Missing,
            }
        }
        fn request_group(&mut self, keys: &[NodeKey]) -> Vec<Demand> {
            keys.iter().map(|k| self.request(k)).collect()
        }
        fn register_dep(&mut self, _key: &NodeKey) {}
    }
