//! Bounded modeled and short wall-clock queue measurements.
//!
//! These tests compare the current fair mailbox with an explicit legacy
//! single-FIFO baseline. The modeled results are deterministic policy evidence;
//! the threaded results are raw local observations and are never interpreted as
//! a speedup claim.

use std::collections::VecDeque;
use std::hint::black_box;
use std::mem::size_of;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Condvar, Mutex};
use std::thread;
use std::time::Instant;

use heterarchy_orchestration_policy::{QueueCapacity, ServiceClass, TimestampMicros};

use super::{QueueDequeue, QueueMailbox, class_index};

const CLASS_COUNT: usize = 5;
const MODELED_BACKGROUND_BACKLOG: u16 = 80;
const MODELED_WORK_BACKLOG: u16 = 80;
const MODELED_LATE_TICKS: u16 = 64;
const MODELED_ARRIVAL_INTERVAL_MICROS: u64 = 100;
const MODELED_SERVICE_MICROS: u64 = 50;
const WALL_EVENTS_PER_CLASS: u16 = 24;
const CPU_WORK_ROUNDS: usize = 64;

#[derive(Clone, Copy, Debug)]
struct MeasureEvent {
    class: ServiceClass,
    sequence: u16,
    enqueued_at_micros: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Percentiles {
    sample_count: usize,
    p50: u64,
    p95: u64,
    p99: u64,
}

#[derive(Debug)]
struct Measurement {
    mode: &'static str,
    capacity: QueueCapacity,
    workload: &'static str,
    attempts: u64,
    admitted: u64,
    rejected: u64,
    per_class: [Percentiles; CLASS_COUNT],
    max_liveness_wait_micros: u64,
    oldest_background_wait_micros: u64,
    throughput_units: u64,
    throughput_per_second: Option<u64>,
    elapsed_micros: u64,
    estimated_storage_bytes: usize,
}

struct MeasurementInput {
    mode: &'static str,
    capacity: QueueCapacity,
    workload: &'static str,
    attempts: u64,
    admitted: u64,
    rejected: u64,
    waits: [Vec<u64>; CLASS_COUNT],
    throughput_units: u64,
    elapsed_micros: u64,
    fair: bool,
}

impl Measurement {
    fn emit(&self, prefix: &str) {
        println!(
            "{prefix} mode={} capacity={:?} workload={} attempts={} admitted={} rejected={} per_class={:?} max_liveness_wait_micros={} oldest_background_wait_micros={} throughput_units={} throughput_per_second={:?} elapsed_micros={} estimated_storage_bytes={} rss_measurement=false",
            self.mode,
            self.capacity,
            self.workload,
            self.attempts,
            self.admitted,
            self.rejected,
            self.per_class,
            self.max_liveness_wait_micros,
            self.oldest_background_wait_micros,
            self.throughput_units,
            self.throughput_per_second,
            self.elapsed_micros,
            self.estimated_storage_bytes,
        );
    }
}

struct LegacyFifo {
    state: Mutex<LegacyState>,
    available: Condvar,
}

struct LegacyState {
    entries: VecDeque<MeasureEvent>,
    capacity: usize,
    closed: bool,
}

impl LegacyFifo {
    fn new(capacity: QueueCapacity) -> Self {
        Self {
            state: Mutex::new(LegacyState {
                entries: VecDeque::new(),
                capacity: usize::from(capacity.slots()),
                closed: false,
            }),
            available: Condvar::new(),
        }
    }

    fn try_enqueue(&self, event: MeasureEvent) -> bool {
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        if state.closed || state.entries.len() >= state.capacity {
            return false;
        }
        state.entries.push_back(event);
        drop(state);
        self.available.notify_one();
        true
    }

    fn wait_dequeue(&self) -> Option<MeasureEvent> {
        let Ok(mut state) = self.state.lock() else {
            return None;
        };
        loop {
            if let Some(event) = state.entries.pop_front() {
                return Some(event);
            }
            if state.closed {
                return None;
            }
            state = self.available.wait(state).ok()?;
        }
    }

    fn close(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.closed = true;
        }
        self.available.notify_all();
    }
}

fn classes() -> [ServiceClass; CLASS_COUNT] {
    ServiceClass::ORDER
}

fn modeled_events() -> Vec<MeasureEvent> {
    let mut events = Vec::with_capacity(
        usize::from(MODELED_BACKGROUND_BACKLOG + MODELED_WORK_BACKLOG)
            + usize::from(MODELED_LATE_TICKS) * 2,
    );
    for sequence in 0..MODELED_BACKGROUND_BACKLOG {
        events.push(MeasureEvent {
            class: ServiceClass::Background,
            sequence,
            enqueued_at_micros: 0,
        });
    }
    for sequence in 0..MODELED_WORK_BACKLOG {
        events.push(MeasureEvent {
            class: ServiceClass::Work,
            sequence,
            enqueued_at_micros: 0,
        });
    }
    for tick in 0..MODELED_LATE_TICKS {
        let arrival = (u64::from(tick) + 1) * MODELED_ARRIVAL_INTERVAL_MICROS;
        events.push(MeasureEvent {
            class: ServiceClass::Liveness,
            sequence: tick,
            enqueued_at_micros: arrival,
        });
        events.push(MeasureEvent {
            class: ServiceClass::Interactive,
            sequence: tick,
            enqueued_at_micros: arrival,
        });
    }
    events
}

fn modeled_measurement(capacity: QueueCapacity, fair: bool) -> Result<Measurement, String> {
    if fair {
        modeled_fair_measurement(capacity)
    } else {
        modeled_legacy_measurement(capacity)
    }
}

fn modeled_fair_measurement(capacity: QueueCapacity) -> Result<Measurement, String> {
    let events = modeled_events();
    let attempts = events.len() as u64;
    let mut waits = [Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new()];
    let mut admitted = 0_u64;
    let mut rejected = 0_u64;
    let mut modeled_clock = 0_u64;
    let mut next_event = 0_usize;
    let mut queued = 0_u64;

    let queue = QueueMailbox::new();
    queue
        .apply_capacity(capacity, 0)
        .map_err(|error| format!("modeled fair capacity applies: {error:?}"))?;
    while next_event < events.len() || queued > 0 {
        if queued == 0 && next_event < events.len() {
            modeled_clock = modeled_clock.max(events[next_event].enqueued_at_micros);
        }
        while next_event < events.len() && events[next_event].enqueued_at_micros <= modeled_clock {
            let event = events[next_event];
            next_event += 1;
            if queue
                .try_enqueue(
                    event.class,
                    event,
                    TimestampMicros(event.enqueued_at_micros),
                )
                .is_ok()
            {
                admitted += 1;
                queued += 1;
            } else {
                rejected += 1;
            }
        }
        if queued == 0 {
            continue;
        }
        let result = queue
            .try_dequeue(TimestampMicros(modeled_clock))
            .map_err(|error| format!("modeled fair dequeue: {error:?}"))?;
        let QueueDequeue::Item { item } = result else {
            return Err("modeled fair queue lost an admitted item".to_owned());
        };
        waits[class_index(item.class)].push(modeled_clock - item.enqueued_at_micros);
        queued -= 1;
        modeled_clock = modeled_clock.saturating_add(MODELED_SERVICE_MICROS);
    }
    Ok(measurement(MeasurementInput {
        mode: "fair",
        capacity,
        workload: "modeled",
        attempts,
        admitted,
        rejected,
        waits,
        throughput_units: admitted,
        elapsed_micros: 0,
        fair: true,
    }))
}

fn modeled_legacy_measurement(capacity: QueueCapacity) -> Result<Measurement, String> {
    let events = modeled_events();
    let attempts = events.len() as u64;
    let mut waits = [Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new()];
    let mut admitted = 0_u64;
    let mut rejected = 0_u64;
    let mut modeled_clock = 0_u64;
    let mut next_event = 0_usize;
    let mut queued = 0_u64;
    let queue = LegacyFifo::new(capacity);
    while next_event < events.len() || queued > 0 {
        if queued == 0 && next_event < events.len() {
            modeled_clock = modeled_clock.max(events[next_event].enqueued_at_micros);
        }
        while next_event < events.len() && events[next_event].enqueued_at_micros <= modeled_clock {
            let event = events[next_event];
            next_event += 1;
            if queue.try_enqueue(event) {
                admitted += 1;
                queued += 1;
            } else {
                rejected += 1;
            }
        }
        if queued == 0 {
            continue;
        }
        let item = queue
            .entries_for_measurement()
            .ok_or_else(|| "modeled legacy queue lost an admitted item".to_owned())?;
        waits[class_index(item.class)].push(modeled_clock - item.enqueued_at_micros);
        queued -= 1;
        modeled_clock = modeled_clock.saturating_add(MODELED_SERVICE_MICROS);
    }
    Ok(measurement(MeasurementInput {
        mode: "legacy_fifo",
        capacity,
        workload: "modeled",
        attempts,
        admitted,
        rejected,
        waits,
        throughput_units: admitted,
        elapsed_micros: 0,
        fair: false,
    }))
}

fn wall_measurement(capacity: QueueCapacity, fair: bool) -> Result<Measurement, String> {
    let start = Instant::now();
    let barrier = Arc::new(Barrier::new(CLASS_COUNT + 1));
    let done_count = Arc::new(AtomicUsize::new(0));
    let rejected = Arc::new(AtomicU64::new(0));
    let admitted = Arc::new(AtomicU64::new(0));
    let mut producers = Vec::with_capacity(CLASS_COUNT);

    let waits = if fair {
        let queue = QueueMailbox::new();
        queue
            .apply_capacity(capacity, 0)
            .map_err(|error| format!("wall fair capacity applies: {error:?}"))?;
        let consumer_queue = queue.clone();
        let consumer_barrier = Arc::clone(&barrier);
        let consumer = thread::spawn(move || {
            consumer_barrier.wait();
            let mut waits = [Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new()];
            consume_fair(&consumer_queue, start, &mut waits).map(|()| waits)
        });
        spawn_fair_producers(
            &mut producers,
            &queue,
            &barrier,
            &done_count,
            &rejected,
            &admitted,
            start,
        );
        for producer in producers {
            producer
                .join()
                .map_err(|_| "fair producer joined".to_owned())?;
        }
        consumer
            .join()
            .map_err(|_| "fair consumer joined".to_owned())??
    } else {
        let queue = Arc::new(LegacyFifo::new(capacity));
        let consumer_queue = Arc::clone(&queue);
        let consumer_barrier = Arc::clone(&barrier);
        let consumer = thread::spawn(move || {
            consumer_barrier.wait();
            let mut waits = [Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new()];
            consume_legacy(&consumer_queue, start, &mut waits);
            waits
        });
        spawn_legacy_producers(
            &mut producers,
            &queue,
            &barrier,
            &done_count,
            &rejected,
            &admitted,
            start,
        );
        for producer in producers {
            producer
                .join()
                .map_err(|_| "legacy producer joined".to_owned())?;
        }
        consumer
            .join()
            .map_err(|_| "legacy consumer joined".to_owned())?
    };

    let attempts = u64::from(WALL_EVENTS_PER_CLASS) * CLASS_COUNT as u64;
    let admitted = admitted.load(Ordering::Acquire);
    let rejected = rejected.load(Ordering::Acquire);
    Ok(measurement(MeasurementInput {
        mode: if fair { "fair" } else { "legacy_fifo" },
        capacity,
        workload: "wall_clock_observation",
        attempts,
        admitted,
        rejected,
        waits,
        throughput_units: admitted,
        elapsed_micros: start.elapsed().as_micros().try_into().unwrap_or(u64::MAX),
        fair,
    }))
}

fn spawn_fair_producers(
    producers: &mut Vec<thread::JoinHandle<()>>,
    queue: &QueueMailbox<MeasureEvent>,
    barrier: &Arc<Barrier>,
    done_count: &Arc<AtomicUsize>,
    rejected: &Arc<AtomicU64>,
    admitted: &Arc<AtomicU64>,
    start: Instant,
) {
    for class in classes() {
        let queue = queue.clone();
        let barrier = Arc::clone(barrier);
        let done_count = Arc::clone(done_count);
        let rejected = Arc::clone(rejected);
        let admitted = Arc::clone(admitted);
        producers.push(thread::spawn(move || {
            barrier.wait();
            for sequence in 0..WALL_EVENTS_PER_CLASS {
                short_cpu_work(u64::from(sequence) + class_index(class) as u64);
                let event = MeasureEvent {
                    class,
                    sequence,
                    enqueued_at_micros: elapsed_micros(start),
                };
                if queue
                    .try_enqueue(class, event, TimestampMicros(event.enqueued_at_micros))
                    .is_ok()
                {
                    admitted.fetch_add(1, Ordering::AcqRel);
                } else {
                    rejected.fetch_add(1, Ordering::AcqRel);
                }
            }
            if done_count.fetch_add(1, Ordering::AcqRel) + 1 == CLASS_COUNT {
                let _ = queue.close();
            }
        }));
    }
}

fn spawn_legacy_producers(
    producers: &mut Vec<thread::JoinHandle<()>>,
    queue: &Arc<LegacyFifo>,
    barrier: &Arc<Barrier>,
    done_count: &Arc<AtomicUsize>,
    rejected: &Arc<AtomicU64>,
    admitted: &Arc<AtomicU64>,
    start: Instant,
) {
    for class in classes() {
        let queue = Arc::clone(queue);
        let barrier = Arc::clone(barrier);
        let done_count = Arc::clone(done_count);
        let rejected = Arc::clone(rejected);
        let admitted = Arc::clone(admitted);
        producers.push(thread::spawn(move || {
            barrier.wait();
            for sequence in 0..WALL_EVENTS_PER_CLASS {
                short_cpu_work(u64::from(sequence) + class_index(class) as u64);
                let event = MeasureEvent {
                    class,
                    sequence,
                    enqueued_at_micros: elapsed_micros(start),
                };
                if queue.try_enqueue(event) {
                    admitted.fetch_add(1, Ordering::AcqRel);
                } else {
                    rejected.fetch_add(1, Ordering::AcqRel);
                }
            }
            if done_count.fetch_add(1, Ordering::AcqRel) + 1 == CLASS_COUNT {
                queue.close();
            }
        }));
    }
}

fn consume_fair(
    queue: &QueueMailbox<MeasureEvent>,
    start: Instant,
    waits: &mut [Vec<u64>; CLASS_COUNT],
) -> Result<(), String> {
    loop {
        match queue
            .wait_dequeue(TimestampMicros(elapsed_micros(start)))
            .map_err(|error| format!("fair consumer dispatch: {error:?}"))?
        {
            QueueDequeue::Item { item } => {
                waits[class_index(item.class)]
                    .push(elapsed_micros(start) - item.enqueued_at_micros);
                short_cpu_work(u64::from(item.sequence));
            }
            QueueDequeue::Empty => {}
            QueueDequeue::Closed => break,
        }
    }
    Ok(())
}

fn consume_legacy(queue: &Arc<LegacyFifo>, start: Instant, waits: &mut [Vec<u64>; CLASS_COUNT]) {
    while let Some(item) = queue.wait_dequeue() {
        waits[class_index(item.class)].push(elapsed_micros(start) - item.enqueued_at_micros);
        short_cpu_work(u64::from(item.sequence));
    }
}

fn measurement(input: MeasurementInput) -> Measurement {
    let max_liveness_wait_micros = input.waits[0].iter().copied().max().unwrap_or(0);
    let oldest_background_wait_micros = input.waits[4].iter().copied().max().unwrap_or(0);
    let per_class = input.waits.map(|mut values| {
        let sample_count = values.len();
        values.sort_unstable();
        Percentiles {
            sample_count,
            p50: percentile(&values, 50),
            p95: percentile(&values, 95),
            p99: percentile(&values, 99),
        }
    });
    let lane_storage = if input.fair { 5 } else { 1 } * size_of::<VecDeque<MeasureEvent>>();
    let estimated_storage_bytes =
        usize::from(input.capacity.slots()) * size_of::<MeasureEvent>() + lane_storage;
    Measurement {
        mode: input.mode,
        capacity: input.capacity,
        workload: input.workload,
        attempts: input.attempts,
        admitted: input.admitted,
        rejected: input.rejected,
        per_class,
        max_liveness_wait_micros,
        oldest_background_wait_micros,
        throughput_units: input.throughput_units,
        throughput_per_second: (input.elapsed_micros != 0).then(|| {
            input
                .throughput_units
                .saturating_mul(1_000_000)
                .checked_div(input.elapsed_micros)
                .unwrap_or(0)
        }),
        elapsed_micros: input.elapsed_micros,
        estimated_storage_bytes,
    }
}

fn percentile(values: &[u64], percentile: usize) -> u64 {
    if values.is_empty() {
        return 0;
    }
    let rank = ((values.len() * percentile).saturating_add(99) / 100).max(1);
    values[rank.min(values.len()) - 1]
}

fn elapsed_micros(start: Instant) -> u64 {
    start.elapsed().as_micros().try_into().unwrap_or(u64::MAX)
}

fn short_cpu_work(seed: u64) {
    let mut value = seed;
    for _ in 0..CPU_WORK_ROUNDS {
        value = value
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
    }
    black_box(value);
}

#[test]
fn queue_measurements_capture_modeled_and_wall_clock_observations() -> Result<(), String> {
    println!(
        "queue_measurement_schema=v2 rss_measurement=false modeled_schedule=background_work_backlog_then_liveness_interactive arrivals service_micros={MODELED_SERVICE_MICROS}"
    );
    for capacity in QueueCapacity::ALL {
        for fair in [false, true] {
            let modeled = modeled_measurement(capacity, fair)?;
            assert_eq!(modeled.attempts, modeled.admitted + modeled.rejected);
            modeled.emit("MODELED");
            let wall = wall_measurement(capacity, fair)?;
            assert_eq!(wall.attempts, wall.admitted + wall.rejected);
            assert!(wall.elapsed_micros > 0);
            assert!(wall.throughput_per_second.is_some());
            wall.emit("WALL_CLOCK");
        }
    }
    Ok(())
}

impl LegacyFifo {
    fn entries_for_measurement(&self) -> Option<MeasureEvent> {
        self.state.lock().ok()?.entries.pop_front()
    }
}
