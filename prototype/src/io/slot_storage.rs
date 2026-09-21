use std::collections::VecDeque;

struct Slot<T: Sized> {
    epoch: u32,
    item: Option<T>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct IndexSlotId {
    idx: u32,
}

pub struct IndexableSlotStorage<T: Sized> {
    slots: Vec<Slot<T>>,
    free: VecDeque<u32>,
}

impl<T: Sized> IndexableSlotStorage<T> {
    pub fn new(len: usize) -> Self {
        assert!(
            len <= u32::MAX as usize,
            "slot count exceeds the index width"
        );
        Self {
            slots: (0..len)
                .map(|_| Slot {
                    epoch: 0,
                    item: None,
                })
                .collect(),
            free: (0..len as u32).collect(),
        }
    }

    pub fn get(&mut self) -> Option<IndexSlotId> {
        let idx = self.free.pop_front()?;
        Some(IndexSlotId { idx })
    }

    pub fn set(&mut self, id: IndexSlotId, item: T) {
        let slot = &mut self.slots[id.idx as usize];
        debug_assert!(slot.item.is_none(), "slot already occupied");
        slot.item = Some(item);
    }

    pub fn put(&mut self, id: IndexSlotId) -> Option<T> {
        let slot = &mut self.slots[id.idx as usize];
        slot.epoch = slot.epoch.wrapping_add(1);
        self.free.push_front(id.idx);
        slot.item.take()
    }

    pub fn index(&self, id: IndexSlotId) -> Option<&T> {
        self.slots[id.idx as usize].item.as_ref()
    }

    pub fn index_mut(&mut self, id: IndexSlotId) -> Option<&mut T> {
        self.slots[id.idx as usize].item.as_mut()
    }
}
