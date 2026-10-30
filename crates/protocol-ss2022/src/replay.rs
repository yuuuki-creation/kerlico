//! 只在完整报文认证及语义校验后推进的滑动回放窗口。

#[derive(Default)]
pub(crate) struct ReplayWindow {
    maximum: Option<u64>,
    bits: [u64; 32],
}

impl ReplayWindow {
    pub fn accept(&mut self, id: u64) -> bool {
        if let Some(maximum) = self.maximum {
            if id <= maximum && maximum - id >= 2048 {
                return false;
            }
            if id > maximum {
                let advance = (id - maximum).min(2048);
                for step in 1..=advance {
                    let index = (maximum.wrapping_add(step) % 2048) as usize;
                    self.bits[index / 64] &= !(1u64 << (index % 64));
                }
                self.maximum = Some(id);
            }
        } else {
            self.maximum = Some(id);
        }
        let index = (id % 2048) as usize;
        let mask = 1u64 << (index % 64);
        if self.bits[index / 64] & mask != 0 {
            return false;
        }
        self.bits[index / 64] |= mask;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_replays_and_old_packets_without_rejecting_reordering() {
        let mut window = ReplayWindow::default();
        assert!(window.accept(10));
        assert!(window.accept(8));
        assert!(!window.accept(8));
        assert!(window.accept(2058));
        assert!(!window.accept(10));
        assert!(window.accept(2057));
        assert!(window.accept(u64::MAX));
        assert!(!window.accept(u64::MAX));
        assert!(window.accept(u64::MAX - 1));
        assert!(!window.accept(0));
    }
}
