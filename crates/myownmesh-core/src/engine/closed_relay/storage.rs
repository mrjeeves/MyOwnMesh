//! Fixed-capacity storage for the engine-owned Closed-relay registries.
//!
//! The tables in this module deliberately never compact or resize.  A slot
//! may be reserved while its value is being observed outside a registry lock;
//! this keeps the physical identity stable across an await and lets the
//! caller either restore the exact value or release the exact slot.

pub(crate) struct FixedTable<T> {
    slots: Box<[FixedSlot<T>]>,
    live: usize,
    reserved: usize,
}

struct FixedSlot<T> {
    value: Option<T>,
    reserved: bool,
}

impl<T> FixedTable<T> {
    pub(crate) fn allocation_bytes(capacity: usize) -> Option<usize> {
        std::mem::size_of::<FixedSlot<T>>().checked_mul(capacity)
    }

    pub(crate) fn new(capacity: usize) -> Self {
        let slots = std::iter::repeat_with(|| FixedSlot {
            value: None,
            reserved: false,
        })
        .take(capacity)
        .collect();
        Self {
            slots,
            live: 0,
            reserved: 0,
        }
    }

    pub(crate) fn capacity(&self) -> usize {
        self.slots.len()
    }

    pub(crate) fn len(&self) -> usize {
        self.live
    }

    pub(crate) fn is_full(&self) -> bool {
        match self.live.checked_add(self.reserved) {
            Some(occupied) => occupied >= self.capacity(),
            None => true,
        }
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = &T> {
        self.slots.iter().filter_map(|slot| slot.value.as_ref())
    }

    pub(crate) fn iter_mut(&mut self) -> impl Iterator<Item = &mut T> {
        self.slots.iter_mut().filter_map(|slot| slot.value.as_mut())
    }

    pub(crate) fn position(&self, mut predicate: impl FnMut(&T) -> bool) -> Option<usize> {
        self.slots
            .iter()
            .enumerate()
            .filter_map(|(index, slot)| slot.value.as_ref().map(|value| (index, value)))
            .find_map(|(index, value)| predicate(value).then_some(index))
    }

    pub(crate) fn get(&self, index: usize) -> Option<&T> {
        self.slots.get(index)?.value.as_ref()
    }

    pub(crate) fn get_mut(&mut self, index: usize) -> Option<&mut T> {
        self.slots.get_mut(index)?.value.as_mut()
    }

    pub(crate) fn insert(&mut self, value: T) -> Result<usize, T> {
        let Some((index, slot)) = self
            .slots
            .iter_mut()
            .enumerate()
            .find(|(_, slot)| !slot.reserved && slot.value.is_none())
        else {
            return Err(value);
        };
        slot.value = Some(value);
        self.live += 1;
        Ok(index)
    }

    pub(crate) fn remove(&mut self, index: usize) -> Option<T> {
        let slot = self.slots.get_mut(index)?;
        if slot.reserved {
            return None;
        }
        let value = slot.value.take()?;
        self.live -= 1;
        Some(value)
    }

    pub(crate) fn take_any(&mut self) -> Option<T> {
        let index = self.position(|_| true)?;
        self.remove(index)
    }

    pub(crate) fn reserve_any(&mut self) -> Option<(usize, T)> {
        let index = self.position(|_| true)?;
        let value = self.reserve(index)?;
        Some((index, value))
    }

    /// Extract a value while reserving its physical slot for the caller.
    pub(crate) fn reserve(&mut self, index: usize) -> Option<T> {
        let slot = self.slots.get_mut(index)?;
        if slot.reserved {
            return None;
        }
        let value = slot.value.take()?;
        slot.reserved = true;
        self.live -= 1;
        self.reserved += 1;
        Some(value)
    }

    pub(crate) fn restore(&mut self, index: usize, value: T) -> Result<(), T> {
        let Some(slot) = self.slots.get_mut(index) else {
            return Err(value);
        };
        if !slot.reserved || slot.value.is_some() {
            return Err(value);
        }
        slot.value = Some(value);
        slot.reserved = false;
        self.live += 1;
        self.reserved -= 1;
        Ok(())
    }

    /// Restore a value to a reservation whose physical identity is part of a
    /// live ownership guard.  A mismatch is an invariant violation rather
    /// than a recoverable queue refusal: silently dropping the value would
    /// lose the guarded custody.
    pub(crate) fn restore_exact(&mut self, index: usize, value: T) {
        let slot = self
            .slots
            .get_mut(index)
            .expect("exact reservation index remains in its table");
        assert!(
            slot.reserved && slot.value.is_none(),
            "exact reservation slot was changed before restoration"
        );
        slot.value = Some(value);
        slot.reserved = false;
        self.live += 1;
        self.reserved -= 1;
    }

    pub(crate) fn release_reserved(&mut self, index: usize) -> bool {
        let Some(slot) = self.slots.get_mut(index) else {
            return false;
        };
        if !slot.reserved || slot.value.is_some() {
            return false;
        }
        slot.reserved = false;
        self.reserved -= 1;
        true
    }
}

/// A fixed-capacity FIFO.  Removing the middle of the queue shifts values in
/// place, but never changes the physical allocation or its capacity.
pub(crate) struct FixedFifo<T> {
    slots: Box<[Option<T>]>,
    head: usize,
    len: usize,
}

impl<T> FixedFifo<T> {
    pub(crate) fn allocation_bytes(capacity: usize) -> Option<usize> {
        std::mem::size_of::<Option<T>>().checked_mul(capacity)
    }

    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            slots: std::iter::repeat_with(|| None).take(capacity).collect(),
            head: 0,
            len: 0,
        }
    }

    pub(crate) fn capacity(&self) -> usize {
        self.slots.len()
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }

    pub(crate) fn is_full(&self) -> bool {
        self.len >= self.capacity()
    }

    fn physical(&self, logical: usize) -> usize {
        (self.head + logical) % self.capacity().max(1)
    }

    pub(crate) fn get(&self, logical: usize) -> Option<&T> {
        if logical >= self.len {
            return None;
        }
        self.slots.get(self.physical(logical))?.as_ref()
    }

    pub(crate) fn push_back(&mut self, value: T) -> Result<(), T> {
        if self.is_full() || self.capacity() == 0 {
            return Err(value);
        }
        let index = self.physical(self.len);
        self.slots[index] = Some(value);
        self.len += 1;
        Ok(())
    }

    pub(crate) fn pop_front(&mut self) -> Option<T> {
        if self.len == 0 {
            return None;
        }
        let index = self.head;
        let value = self.slots[index].take();
        self.head = self.physical(1);
        self.len -= 1;
        if self.len == 0 {
            self.head = 0;
        }
        value
    }

    pub(crate) fn remove(&mut self, logical: usize) -> Option<T> {
        if logical >= self.len {
            return None;
        }
        let index = self.physical(logical);
        let value = self.slots[index].take();
        for offset in logical..self.len.saturating_sub(1) {
            let from = self.physical(offset + 1);
            let to = self.physical(offset);
            self.slots[to] = self.slots[from].take();
        }
        self.len -= 1;
        if self.len == 0 {
            self.head = 0;
        }
        value
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = &T> {
        (0..self.len).filter_map(|index| self.get(index))
    }
}

impl<T> Default for FixedFifo<T> {
    fn default() -> Self {
        Self::new(0)
    }
}

#[cfg(test)]
mod tests {
    use super::{FixedFifo, FixedTable};

    #[test]
    fn reserved_table_slot_restores_exactly() {
        let mut table = FixedTable::new(2);
        let first = table.insert("first").expect("first slot");
        let second = table.insert("second").expect("second slot");
        let (reserved, value) = table.reserve_any().expect("reserved value");
        assert_eq!(value, "first");
        assert_eq!(table.insert("third"), Err("third"));
        assert!(table.restore(reserved, value).is_ok());
        assert_eq!(table.remove(second), Some("second"));
        assert_eq!(table.insert("third"), Ok(second));
        assert_eq!(table.get(first), Some(&"first"));
        assert_eq!(table.get(second), Some(&"third"));
    }

    #[test]
    fn terminalized_reservation_cannot_release_a_reused_slot() {
        let mut table = FixedTable::new(1);
        let slot = table.insert("old").expect("old slot");
        let old = table.reserve(slot).expect("old reservation");
        table.restore_exact(slot, old);
        assert!(!table.release_reserved(slot));

        let _ = table.remove(slot).expect("old value");
        assert_eq!(table.insert("successor"), Ok(slot));
        let successor = table.reserve(slot).expect("successor reservation");
        table.restore_exact(slot, successor);
        assert!(!table.release_reserved(slot));
    }

    #[test]
    fn fifo_middle_removal_preserves_order_and_capacity() {
        let mut fifo = FixedFifo::new(3);
        fifo.push_back(1).expect("first");
        fifo.push_back(2).expect("second");
        fifo.push_back(3).expect("third");
        assert_eq!(fifo.remove(1), Some(2));
        assert_eq!(fifo.capacity(), 3);
        assert_eq!(fifo.pop_front(), Some(1));
        assert_eq!(fifo.pop_front(), Some(3));
        assert_eq!(fifo.pop_front(), None);
    }
}
