use std::collections::VecDeque;

struct Slot<T: Sized> {
    item: Option<T>,
    generation: u16,
}

impl<T: Sized> Slot<T> {
    const EMPTY: Self = Self {
        item: None,
        generation: 1,
    };

    /// Takes the item and retires the id, cycling the generation `1..=u16::MAX`.
    fn retire(&mut self) -> Option<T> {
        self.generation = (self.generation % u16::MAX) + 1;
        self.item.take()
    }
}

/// Slot index paired with the generation the slot carried when the id was issued.
/// Generation 0 is never issued, so `default()` matches no live slot.
#[derive(Default, Clone, Copy, PartialEq, Eq, Debug)]
pub struct IndexSlotId {
    bits: u32,
}

impl IndexSlotId {
    const GEN_SHIFT: u32 = 16;
    const IDX_MASK: u32 = u16::MAX as u32;

    #[inline]
    pub(super) fn new(idx: u16, generation: u16) -> Self {
        Self {
            bits: ((generation as u32) << Self::GEN_SHIFT) | idx as u32,
        }
    }

    #[inline]
    pub(super) fn idx(self) -> u32 {
        self.bits & Self::IDX_MASK
    }

    #[inline]
    pub(super) fn from_bits(bits: u32) -> Self {
        Self { bits }
    }

    #[inline]
    pub(super) fn bits(self) -> u32 {
        self.bits
    }

    #[inline]
    pub(super) fn generation(self) -> u16 {
        (self.bits >> Self::GEN_SHIFT) as u16
    }
}

pub struct IndexableSlotStorage<T: Sized> {
    slots: Vec<Slot<T>>,
    free: VecDeque<u32>,
}

impl<T: Sized> IndexableSlotStorage<T> {
    pub fn new(len: usize) -> Self {
        assert!(
            len <= u16::MAX as usize,
            "slot count exceeds the index width"
        );
        Self {
            slots: (0..len).map(|_| Slot::EMPTY).collect(),
            free: (0..len as u32).collect(),
        }
    }

    pub fn get(&mut self) -> Option<IndexSlotId> {
        let idx = self.free.pop_front()?;
        Some(IndexSlotId::new(
            idx as u16,
            self.slots[idx as usize].generation,
        ))
    }

    pub fn set(&mut self, id: IndexSlotId, item: T) {
        let slot = &mut self.slots[id.idx() as usize];
        debug_assert_eq!(id.generation(), slot.generation, "set through a stale id");
        debug_assert!(slot.item.is_none(), "slot already occupied");
        slot.item = Some(item);
    }

    pub fn put(&mut self, id: IndexSlotId) -> Option<T> {
        let slot = &mut self.slots[id.idx() as usize];
        assert_eq!(
            id.generation(),
            slot.generation,
            "slot freed through a stale id"
        );
        let item = slot.retire();
        self.free.push_front(id.idx());
        item
    }

    pub fn index(&self, id: IndexSlotId) -> Option<&T> {
        let slot = &self.slots[id.idx() as usize];
        (slot.generation == id.generation())
            .then_some(slot.item.as_ref())
            .flatten()
    }

    pub fn index_mut(&mut self, id: IndexSlotId) -> Option<&mut T> {
        let slot = &mut self.slots[id.idx() as usize];
        (slot.generation == id.generation())
            .then_some(slot.item.as_mut())
            .flatten()
    }

    pub fn ids(&self) -> impl Iterator<Item = IndexSlotId> + '_ {
        self.slots
            .iter()
            .enumerate()
            .filter(|(_, slot)| slot.item.is_some())
            .map(|(idx, slot)| IndexSlotId::new(idx as u16, slot.generation))
    }

    pub fn ids_mut(&mut self) -> impl Iterator<Item = &mut T> + '_ {
        self.slots.iter_mut().filter_map(|slot| slot.item.as_mut())
    }
}

pub const SMALL_SLOT_CAPACITY: usize = u128::BITS as usize;

pub struct SmallSlotStorage<T: Sized> {
    slots: [Slot<T>; SMALL_SLOT_CAPACITY],
    used: u128,
}

impl<T: Sized> SmallSlotStorage<T> {
    /// Range checked slot index. A wide shift is masked in release builds.
    #[inline]
    fn slot_index(id: IndexSlotId) -> usize {
        let idx = id.idx() as usize;
        assert!(
            idx < SMALL_SLOT_CAPACITY,
            "slot id {} past the {} slots of this store",
            idx,
            SMALL_SLOT_CAPACITY
        );
        idx
    }

    pub fn new() -> Self {
        Self {
            slots: [Slot::EMPTY; SMALL_SLOT_CAPACITY],
            used: 0,
        }
    }

    pub fn get(&mut self) -> Option<IndexSlotId> {
        let idx = (!self.used).trailing_zeros() as usize;
        if idx >= SMALL_SLOT_CAPACITY {
            return None;
        }
        self.used |= 1u128 << idx;
        Some(IndexSlotId::new(idx as u16, self.slots[idx].generation))
    }

    pub fn set(&mut self, id: IndexSlotId, item: T) {
        let idx = Self::slot_index(id);
        debug_assert!(self.used & (1u128 << idx) != 0, "slot not handed out");
        let slot = &mut self.slots[idx];
        debug_assert_eq!(id.generation(), slot.generation, "set through a stale id");
        debug_assert!(slot.item.is_none(), "slot already occupied");
        slot.item = Some(item);
    }

    pub fn put(&mut self, id: IndexSlotId) -> Option<T> {
        let idx = Self::slot_index(id);
        let slot = &mut self.slots[idx];
        assert_eq!(
            id.generation(),
            slot.generation,
            "slot freed through a stale id"
        );
        let item = slot.retire();
        self.used &= !(1u128 << idx);
        item
    }

    pub fn occupied(&self) -> usize {
        self.used.count_ones() as usize
    }

    /// Adopts the generation of a free slot, rejects a stale one on an occupied slot.
    pub fn get_or_insert(&mut self, id: IndexSlotId, init: impl FnOnce() -> T) -> Option<&mut T> {
        let idx = Self::slot_index(id);
        if id.generation() == 0 {
            return None;
        }
        let slot = &mut self.slots[idx];
        if self.used & (1u128 << idx) == 0 {
            self.used |= 1u128 << idx;
            slot.generation = id.generation();
        } else if slot.generation != id.generation() {
            return None;
        }
        Some(slot.item.get_or_insert_with(init))
    }

    pub fn index(&self, id: IndexSlotId) -> Option<&T> {
        let slot = &self.slots[Self::slot_index(id)];
        (slot.generation == id.generation())
            .then(|| slot.item.as_ref())
            .flatten()
    }

    pub fn index_mut(&mut self, id: IndexSlotId) -> Option<&mut T> {
        let slot = &mut self.slots[Self::slot_index(id)];
        (slot.generation == id.generation())
            .then(|| slot.item.as_mut())
            .flatten()
    }

    pub fn ids(&self) -> impl Iterator<Item = IndexSlotId> + '_ {
        let mut used = self.used;
        std::iter::from_fn(move || {
            if used == 0 {
                return None;
            }
            let idx = used.trailing_zeros();
            used &= used - 1;
            Some(idx)
        })
        .filter(|&idx| self.slots[idx as usize].item.is_some())
        .map(|idx| IndexSlotId::new(idx as u16, self.slots[idx as usize].generation))
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = (IndexSlotId, &mut T)> + '_ {
        self.slots.iter_mut().enumerate().filter_map(|(idx, slot)| {
            let generation = slot.generation;
            slot.item
                .as_mut()
                .map(|item| (IndexSlotId::new(idx as u16, generation), item))
        })
    }
}

////////////////////////////////////////////////////////////////////////////////
//  Tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ids_lists_occupied_slots() {
        let mut store = IndexableSlotStorage::new(4);
        assert_eq!(store.ids().count(), 0);
        let ids: Vec<_> = (0..4)
            .map(|item| {
                let id = store.get().unwrap();
                store.set(id, item);
                id
            })
            .collect();
        assert_eq!(store.ids().collect::<Vec<_>>(), ids);
        store.put(ids[1]);
        assert_eq!(store.ids().collect::<Vec<_>>(), [ids[0], ids[2], ids[3]]);
    }

    #[test]
    fn test_stale_id_does_not_resolve() {
        let mut store = IndexableSlotStorage::new(1);
        let old = store.get().unwrap();
        store.set(old, 7);
        assert_eq!(store.put(old), Some(7));
        let new = store.get().unwrap();
        store.set(new, 9);
        assert_eq!(old.idx(), new.idx(), "the index comes back");
        assert_ne!(old, new, "the generation moved on");
        assert_eq!(store.index(old), None);
        assert_eq!(store.index(new), Some(&9));
    }

    #[test]
    #[should_panic(expected = "stale id")]
    fn test_double_free_panics() {
        let mut store = IndexableSlotStorage::new(1);
        let id = store.get().unwrap();
        store.set(id, 7);
        store.put(id);
        store.get().unwrap();
        store.put(id);
    }

    #[test]
    fn test_generation_never_reaches_zero() {
        let mut store = IndexableSlotStorage::<u32>::new(1);
        for _ in 0..(u16::MAX as u32 + 3) {
            let id = store.get().unwrap();
            assert_ne!(id.generation(), 0, "generation 0 was issued");
            store.put(id);
        }
    }

    #[test]
    fn test_small_ids_lists_occupied_slots() {
        let mut store = SmallSlotStorage::new();
        assert_eq!(store.ids().count(), 0);
        let ids: Vec<_> = (0..4)
            .map(|item| {
                let id = store.get().unwrap();
                store.set(id, item);
                id
            })
            .collect();
        assert_eq!(store.ids().collect::<Vec<_>>(), ids);
        assert_eq!(store.put(ids[1]), Some(1));
        assert_eq!(store.ids().collect::<Vec<_>>(), [ids[0], ids[2], ids[3]]);
        // the freed index comes back under a new generation
        let reopened = store.get().unwrap();
        assert_eq!(reopened.idx(), ids[1].idx());
        assert_ne!(reopened, ids[1]);
        assert_eq!(store.index(ids[1]), None);
    }

    #[test]
    fn test_small_exhaustion() {
        let mut store = SmallSlotStorage::new();
        for item in 0..SMALL_SLOT_CAPACITY {
            let id = store.get().expect("free slot");
            store.set(id, item);
        }
        assert!(store.get().is_none());
        assert_eq!(store.ids().count(), SMALL_SLOT_CAPACITY);
    }

    #[test]
    fn test_small_reserved_slot_is_not_listed_or_reused() {
        let mut store = SmallSlotStorage::<u32>::new();
        let reserved = store.get().unwrap();
        assert_eq!(store.ids().count(), 0);
        assert_ne!(store.get().unwrap(), reserved);
    }

    #[test]
    fn test_small_get_or_insert_adopts_the_generation() {
        let mut store = SmallSlotStorage::<u32>::new();
        let id = IndexSlotId::new(2, 5);
        assert_eq!(*store.get_or_insert(id, || 7).unwrap(), 7);
        assert_eq!(store.ids().collect::<Vec<_>>(), [id]);
        assert_eq!(*store.get_or_insert(id, || 9).unwrap(), 7, "init ran twice");
        // another generation on the same index is a different stream
        assert!(store.get_or_insert(IndexSlotId::new(2, 6), || 9).is_none());
        assert!(store.get_or_insert(IndexSlotId::new(2, 0), || 9).is_none());
        // the filled slot is not handed out again
        for _ in 0..SMALL_SLOT_CAPACITY - 1 {
            assert_ne!(store.get().unwrap().idx(), id.idx());
        }
        assert!(store.get().is_none());
    }
}
