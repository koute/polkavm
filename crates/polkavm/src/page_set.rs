// TODO: This is inefficient. REWRITE THIS.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;
use core::cmp::Ord;

#[derive(Copy, Clone, Debug)]
struct Interval {
    min: u32,
    max: u32,
}

impl From<(u32, u32)> for Interval {
    fn from((min, max): (u32, u32)) -> Interval {
        Interval { min, max }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum SubResult {
    Disjoint,
    None,
    One(Interval),
    Two(Interval, Interval),
}

impl Interval {
    fn merge(self, rhs: Interval) -> Option<Interval> {
        if (self.min >= rhs.min && self.min <= rhs.max)
            || (rhs.min >= self.min && rhs.min <= self.max)
            || (self.max >= rhs.min && self.max <= rhs.max)
            || (self.max < u32::MAX && self.max + 1 == rhs.min)
            || (rhs.max < u32::MAX && self.min == rhs.max + 1)
        {
            Some(Interval::from((self.min.min(rhs.min), self.max.max(rhs.max))))
        } else {
            None
        }
    }

    fn subtract(existing: Interval, to_remove: Interval) -> SubResult {
        if to_remove.max < existing.min || to_remove.min > existing.max {
            return SubResult::Disjoint;
        }

        if to_remove.min > existing.max || to_remove.max < existing.min {
            SubResult::One(existing)
        } else if to_remove.min <= existing.min && to_remove.max >= existing.max {
            SubResult::None
        } else if to_remove.min <= existing.min && to_remove.max < existing.max {
            SubResult::One(Interval::from((to_remove.max + 1, existing.max)))
        } else if to_remove.min > existing.min && to_remove.max >= existing.max {
            SubResult::One(Interval::from((existing.min, to_remove.min - 1)))
        } else {
            SubResult::Two(
                Interval::from((existing.min, to_remove.min - 1)),
                Interval::from((to_remove.max + 1, existing.max)),
            )
        }
    }
}

#[test]
fn test_interval_merge() {
    assert_eq!(Interval::from((1, 2)).merge(Interval::from((2, 4))), Some(Interval::from((1, 4))));
    assert_eq!(Interval::from((2, 4)).merge(Interval::from((1, 2))), Some(Interval::from((1, 4))));
    assert_eq!(Interval::from((1, 2)).merge(Interval::from((3, 4))), Some(Interval::from((1, 4))));
    assert_eq!(Interval::from((3, 4)).merge(Interval::from((1, 2))), Some(Interval::from((1, 4))));
    assert_eq!(Interval::from((1, 2)).merge(Interval::from((4, 5))), None);
    assert_eq!(Interval::from((4, 5)).merge(Interval::from((1, 2))), None);
    assert_eq!(Interval::from((2, 7)).merge(Interval::from((3, 6))), Some(Interval::from((2, 7))));
    assert_eq!(Interval::from((3, 6)).merge(Interval::from((2, 7))), Some(Interval::from((2, 7))));
}

#[test]
fn test_interval_substract() {
    assert_eq!(
        Interval::subtract((10, 20).into(), (15, 15).into()),
        SubResult::Two((10, 14).into(), (16, 20).into())
    );
    assert_eq!(
        Interval::subtract((10, 20).into(), (14, 16).into()),
        SubResult::Two((10, 13).into(), (17, 20).into())
    );
    assert_eq!(
        Interval::subtract((10, 20).into(), (11, 19).into()),
        SubResult::Two((10, 10).into(), (20, 20).into())
    );
    assert_eq!(Interval::subtract((10, 20).into(), (10, 20).into()), SubResult::None);
    assert_eq!(Interval::subtract((10, 20).into(), (10, 25).into()), SubResult::None);
    assert_eq!(Interval::subtract((10, 20).into(), (5, 20).into()), SubResult::None);

    assert_eq!(
        Interval::subtract((10, 20).into(), (15, 20).into()),
        SubResult::One((10, 14).into())
    );
    assert_eq!(
        Interval::subtract((10, 20).into(), (15, 21).into()),
        SubResult::One((10, 14).into())
    );
    assert_eq!(
        Interval::subtract((10, 20).into(), (20, 20).into()),
        SubResult::One((10, 19).into())
    );

    assert_eq!(
        Interval::subtract((10, 20).into(), (10, 15).into()),
        SubResult::One((16, 20).into())
    );
    assert_eq!(Interval::subtract((10, 20).into(), (9, 15).into()), SubResult::One((16, 20).into()));
    assert_eq!(
        Interval::subtract((10, 20).into(), (10, 10).into()),
        SubResult::One((11, 20).into())
    );

    assert_eq!(Interval::subtract((10, 20).into(), (21, 30).into()), SubResult::Disjoint);
    assert_eq!(Interval::subtract((10, 20).into(), (0, 9).into()), SubResult::Disjoint);
}

impl Ord for Interval {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        // We deliberately ignore `max` here.
        self.min.cmp(&other.min)
    }
}

impl PartialOrd for Interval {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Interval {
    fn eq(&self, other: &Self) -> bool {
        self.min == other.min
    }
}

impl Eq for Interval {}

#[derive(Clone, Debug)]
pub struct PageSet {
    intervals: BTreeSet<Interval>,
}

impl PageSet {
    pub fn new() -> Self {
        PageSet {
            intervals: Default::default(),
        }
    }

    pub fn insert(&mut self, (insert_min, insert_max): (u32, u32)) {
        log::trace!("Insert: ({insert_min}, {insert_max})");
        #[cfg(test)]
        log::trace!("  Existing: {:?}", self.to_vec());

        let mut to_insert = Interval {
            min: insert_min,
            max: insert_max,
        };
        let mut iter = self.intervals.range(
            Interval { min: 0, max: 0 }..=Interval {
                min: insert_max.saturating_add(1),
                max: 0,
            },
        );
        let mut to_remove = Vec::new();
        while let Some(&interval) = iter.next_back() {
            log::trace!("  Check: {interval:?}");
            if let Some(new_interval) = to_insert.merge(interval) {
                log::trace!("    Add: {new_interval:?}");
                log::trace!("    Remove: {interval:?}");
                to_remove.push(interval);
                to_insert = new_interval;
            } else {
                break;
            }
        }

        for interval in to_remove {
            self.intervals.remove(&interval);
        }

        self.intervals.insert(to_insert);
    }

    pub fn contains(&self, (min, max): (u32, u32)) -> bool {
        let mut iter = self.intervals.range(Interval { min: 0, max: 0 }..=Interval { min, max: 0 });
        if let Some(i) = iter.next_back() {
            if min >= i.min && max <= i.max {
                return true;
            }

            if i.max < min {
                return false;
            }
        }

        false
    }

    pub fn is_whole_region_empty(&self, (min, max): (u32, u32)) -> bool {
        let mut iter = self.intervals.range(Interval { min: 0, max: 0 }..=Interval { min: max, max: 0 });
        while let Some(i) = iter.next_back() {
            if i.max < min {
                return true;
            }

            if (i.min >= min && i.max <= max) || (i.max >= min && i.min <= max) {
                return false;
            }
        }

        true
    }

    pub fn remove(&mut self, (removed_min, removed_max): (u32, u32)) {
        let mut iter = self.intervals.range(
            Interval { min: 0, max: 0 }..=Interval {
                min: removed_max.saturating_add(1),
                max: 0,
            },
        );

        log::trace!("Remove: ({removed_min}, {removed_max})");
        #[cfg(test)]
        log::trace!("  Existing: {:?}", self.to_vec());

        let mut to_add = Vec::new();
        let mut to_remove = Vec::new();
        while let Some(&interval) = iter.next_back() {
            log::trace!("  Check: {interval:?}");
            match Interval::subtract(
                interval,
                Interval {
                    min: removed_min,
                    max: removed_max,
                },
            ) {
                SubResult::Disjoint => break,
                SubResult::None => {
                    log::trace!("    Remove: {interval:?}");
                    to_remove.push(interval);
                }
                SubResult::One(i) => {
                    log::trace!("    Add: {i:?}");
                    log::trace!("    Remove: {interval:?}");
                    to_remove.push(interval);
                    to_add.push(i);
                }
                SubResult::Two(i1, i2) => {
                    log::trace!("    Add: {i1:?}");
                    log::trace!("    Add: {i2:?}");
                    log::trace!("    Remove: {interval:?}");
                    to_remove.push(interval);
                    to_add.push(i1);
                    to_add.push(i2);
                }
            }
        }

        for interval in to_remove {
            self.intervals.remove(&interval);
        }

        for interval in to_add {
            self.intervals.insert(interval);
        }
    }

    pub fn clear(&mut self) {
        self.intervals.clear();
    }

    #[allow(dead_code)]
    pub fn iter(&'_ self) -> impl ExactSizeIterator<Item = (u32, u32)> + '_ {
        self.intervals.iter().map(|interval| (interval.min, interval.max))
    }

    #[allow(dead_code)]
    fn to_vec(&self) -> Vec<(u32, u32)> {
        self.iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::PageSet;
    use alloc::vec;

    #[test]
    fn test_page_set_basic() {
        let _ = env_logger::try_init();

        let mut set = PageSet::new();
        set.insert((1, 5));
        assert!(set.contains((1, 5)));
        assert!(set.contains((1, 1)));
        assert!(set.contains((5, 5)));
        assert!(set.contains((2, 4)));
        assert!(!set.contains((0, 1)));
        assert!(!set.contains((0, 2)));
        assert!(!set.contains((4, 6)));
        assert!(!set.contains((5, 6)));

        assert!(set.is_whole_region_empty((0, 0)));
        assert!(!set.is_whole_region_empty((0, 1)));
        assert!(!set.is_whole_region_empty((1, 1)));
        assert!(!set.is_whole_region_empty((1, 5)));
        assert!(!set.is_whole_region_empty((5, 5)));
        assert!(!set.is_whole_region_empty((5, 6)));
        assert!(set.is_whole_region_empty((6, 6)));

        {
            // Insert duplicate.
            let mut set = PageSet::new();
            set.insert((3, 6));
            set.insert((3, 6));
            assert_eq!(set.to_vec(), vec![(3, 6)]);
        }

        {
            // Insert into middle, no-op.
            let mut set = PageSet::new();
            set.insert((3, 6));
            set.insert((4, 5));
            assert_eq!(set.to_vec(), vec![(3, 6)]);
        }

        {
            // Insert bigger on both sides.
            let mut set = PageSet::new();
            set.insert((3, 6));
            set.insert((2, 7));
            assert_eq!(set.to_vec(), vec![(2, 7)]);
        }

        {
            // Insert adjacent on the left.
            let mut set = PageSet::new();
            set.insert((3, 6));
            set.insert((2, 2));
            assert_eq!(set.to_vec(), vec![(2, 6)]);
        }

        {
            // Insert adjacent on the left, 1 overlap.
            let mut set = PageSet::new();
            set.insert((3, 6));
            set.insert((2, 3));
            assert_eq!(set.to_vec(), vec![(2, 6)]);
        }

        {
            // Insert adjacent on the left, 2 overlap.
            let mut set = PageSet::new();
            set.insert((3, 6));
            set.insert((2, 4));
            assert_eq!(set.to_vec(), vec![(2, 6)]);
        }

        {
            // Insert adjacent on the left, whole overlap.
            let mut set = PageSet::new();
            set.insert((3, 6));
            set.insert((2, 6));
            assert_eq!(set.to_vec(), vec![(2, 6)]);
        }

        {
            // Insert adjacent on the right.
            let mut set = PageSet::new();
            set.insert((3, 6));
            set.insert((7, 7));
            assert_eq!(set.to_vec(), vec![(3, 7)]);
        }

        {
            // Insert adjacent on the right, one overlap.
            let mut set = PageSet::new();
            set.insert((3, 6));
            set.insert((6, 7));
            assert_eq!(set.to_vec(), vec![(3, 7)]);
        }

        {
            // Insert adjacent on the right, two overlap.
            let mut set = PageSet::new();
            set.insert((3, 6));
            set.insert((5, 7));
            assert_eq!(set.to_vec(), vec![(3, 7)]);
        }

        {
            // Insert adjacent on the right, whole overlap.
            let mut set = PageSet::new();
            set.insert((3, 6));
            set.insert((3, 7));
            assert_eq!(set.to_vec(), vec![(3, 7)]);
        }

        {
            // Insert disjoint on the right.
            let mut set = PageSet::new();
            set.insert((1, 3));
            set.insert((5, 7));
            assert_eq!(set.to_vec(), vec![(1, 3), (5, 7)]);
        }

        {
            // Insert disjoint on the left.
            let mut set = PageSet::new();
            set.insert((5, 7));
            set.insert((1, 3));
            assert_eq!(set.to_vec(), vec![(1, 3), (5, 7)]);
        }

        {
            // Join disjoint in the middle.
            let mut set = PageSet::new();
            set.insert((0, 2));
            set.insert((6, 8));
            set.insert((4, 4));
            assert_eq!(set.to_vec(), vec![(0, 2), (4, 4), (6, 8)]);
            assert!(set.is_whole_region_empty((3, 3)));
            assert!(set.is_whole_region_empty((5, 5)));
            assert!(set.is_whole_region_empty((9, 9)));
            assert!(!set.is_whole_region_empty((3, 4)));
            assert!(!set.is_whole_region_empty((3, 5)));
            assert!(!set.is_whole_region_empty((3, 5)));
            assert!(!set.is_whole_region_empty((3, 6)));
            assert!(!set.is_whole_region_empty((3, 7)));
            assert!(!set.is_whole_region_empty((3, 8)));
            assert!(!set.is_whole_region_empty((3, 9)));
        }

        {
            // Join in the middle, merge all.
            let mut set = PageSet::new();
            set.insert((0, 2));
            set.insert((6, 8));
            set.insert((3, 5));
            assert_eq!(set.to_vec(), vec![(0, 8)]);
        }

        {
            // Join in the middle, merge all, one overlap.
            let mut set = PageSet::new();
            set.insert((0, 2));
            set.insert((6, 8));
            set.insert((2, 6));
            assert_eq!(set.to_vec(), vec![(0, 8)]);
        }

        {
            // Join in the middle, merge all, two overlap.
            let mut set = PageSet::new();
            set.insert((0, 2));
            set.insert((6, 8));
            set.insert((1, 7));
            assert_eq!(set.to_vec(), vec![(0, 8)]);
        }

        {
            // Join in the middle, merge all, whole overlap.
            let mut set = PageSet::new();
            set.insert((0, 2));
            set.insert((6, 8));
            set.insert((0, 8));
            assert_eq!(set.to_vec(), vec![(0, 8)]);
        }

        {
            // Join in the middle, merge all, extend.
            let mut set = PageSet::new();
            set.insert((1, 3));
            set.insert((5, 7));
            set.insert((0, 8));
            assert_eq!(set.to_vec(), vec![(0, 8)]);
        }

        {
            let mut set = PageSet::new();
            set.insert((0, 100));
            set.insert((120, 130));
            set.insert((140, 140));
            set.insert((150, 150));
            set.insert((160, 160));
            set.insert((170, 180));
            set.insert((200, 300));

            {
                let mut set = set.clone();
                set.insert((100, 200));
                assert_eq!(set.to_vec(), vec![(0, 300)]);
            }

            {
                let mut set = set.clone();
                set.insert((101, 199));
                assert_eq!(set.to_vec(), vec![(0, 300)]);
            }

            {
                let mut set = set.clone();
                set.insert((102, 198));
                assert_eq!(set.to_vec(), vec![(0, 100), (102, 198), (200, 300)]);
            }
        }
    }

    #[test]
    fn test_page_set_remove() {
        let _ = env_logger::try_init();

        let mut set = PageSet::new();
        set.insert((20, 30));

        // Remove nonexisting on the left.
        set.remove((10, 19));
        assert_eq!(set.to_vec(), vec![(20, 30)]);

        // Remove nonexisting on the right.
        set.remove((31, 40));
        assert_eq!(set.to_vec(), vec![(20, 30)]);

        {
            let mut set = set.clone();
            set.remove((10, 20));
            assert_eq!(set.to_vec(), vec![(21, 30)]);
        }

        {
            let mut set = set.clone();
            set.remove((10, 21));
            assert_eq!(set.to_vec(), vec![(22, 30)]);
        }

        {
            let mut set = set.clone();
            set.remove((10, 29));
            assert_eq!(set.to_vec(), vec![(30, 30)]);
        }

        {
            let mut set = set.clone();
            set.remove((10, 30));
            assert_eq!(set.to_vec(), vec![]);
        }

        {
            let mut set = set.clone();
            set.remove((10, 40));
            assert_eq!(set.to_vec(), vec![]);
        }

        {
            let mut set = set.clone();
            set.remove((30, 40));
            assert_eq!(set.to_vec(), vec![(20, 29)]);
        }

        {
            let mut set = set.clone();
            set.remove((29, 40));
            assert_eq!(set.to_vec(), vec![(20, 28)]);
        }

        {
            let mut set = set.clone();
            set.remove((21, 40));
            assert_eq!(set.to_vec(), vec![(20, 20)]);
        }

        {
            let mut set = set.clone();
            set.remove((20, 40));
            assert_eq!(set.to_vec(), vec![]);
        }

        {
            let mut set = set.clone();
            set.remove((10, 40));
            assert_eq!(set.to_vec(), vec![]);
        }
    }
}
