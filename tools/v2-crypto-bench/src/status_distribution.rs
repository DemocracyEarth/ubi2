//! Deterministic transport bakeoff for v2 credential-status distribution.
//!
//! These are fixed-width binary lower bounds, not a production wire format.
//! The model deliberately keeps the feed public and unkeyed so a holder never
//! reveals a private status identifier to a witness endpoint.

use serde::Serialize;
use std::collections::BTreeSet;

pub const SPARSE_STATUS_DEPTH: usize = 96;
pub const PACKED_STATUS_DEPTH: usize = 24;
pub const PACKED_STATUS_BITS_PER_CHUNK: usize = 256;

const FIELD_BYTES: u64 = 32;
const EPOCH_BYTES: u64 = 4;
const CHECKPOINT_TRANSITION_BYTES: u64 = EPOCH_BYTES * 2 + FIELD_BYTES * 2;
const CHECKPOINT_BYTES: u64 = EPOCH_BYTES + FIELD_BYTES;
const SPARSE_INDEX_BYTES: u64 = SPARSE_STATUS_DEPTH.div_ceil(8) as u64;
const PACKED_CHUNK_INDEX_BYTES: u64 = PACKED_STATUS_DEPTH.div_ceil(8) as u64;
const STATUS_SEED: u64 = 0x55_42_49_32_53_54_41_54;

#[derive(Clone, Copy, Debug)]
struct Workload {
    name: &'static str,
    credential_population: u64,
    changed_statuses: usize,
}

const WORKLOADS: [Workload; 3] = [
    Workload {
        name: "regional-normal",
        credential_population: 100_000_000,
        changed_statuses: 1_000,
    },
    Workload {
        name: "regional-stress",
        credential_population: 100_000_000,
        changed_statuses: 100_000,
    },
    Workload {
        name: "global-stress",
        credential_population: 1_000_000_000,
        changed_statuses: 100_000,
    },
];

#[derive(Debug, Serialize)]
pub struct StatusDistributionReport {
    pub schema: &'static str,
    pub warning: &'static str,
    pub privacy_model: &'static str,
    pub status_allocation_model: &'static str,
    pub sparse_depth: usize,
    pub packed_depth: usize,
    pub packed_statuses_per_chunk: usize,
    pub results: Vec<StatusDistributionWorkloadReport>,
}

#[derive(Debug, Serialize)]
pub struct StatusDistributionWorkloadReport {
    pub name: &'static str,
    pub credential_population: u64,
    pub changed_statuses: usize,
    pub sparse_merkle: SparseMerkleBatchEstimate,
    pub packed_status: PackedStatusBatchEstimate,
}

#[derive(Debug, Serialize)]
pub struct SparseMerkleBatchEstimate {
    pub changed_leaves: usize,
    pub multiproof_siblings: usize,
    pub holder_witness_floor_bytes: u64,
    pub unbatched_delta_bytes: u64,
    pub batch_patch_bytes: u64,
    pub batch_reduction_basis_points: u64,
}

#[derive(Debug, Serialize)]
pub struct PackedStatusBatchEstimate {
    pub changed_chunks: usize,
    pub multiproof_siblings: usize,
    pub holder_witness_floor_bytes: u64,
    pub batch_patch_bytes: u64,
    pub full_snapshot_bytes: u64,
    pub selected_delivery: DeliveryMode,
    pub selected_delivery_bytes: u64,
    pub reduction_vs_sparse_batch_basis_points: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DeliveryMode {
    BatchPatch,
    FullSnapshot,
}

pub fn run_status_distribution_bakeoff() -> StatusDistributionReport {
    let results = WORKLOADS
        .into_iter()
        .map(estimate_workload)
        .collect::<Vec<_>>();

    StatusDistributionReport {
        schema: "org.proofofhumanity.v2-status-distribution-bakeoff/1",
        warning: "research lower bounds only; no production accumulator, wire format, checkpoint authority or status assignment is ratified",
        privacy_model: "public unkeyed batch/snapshot distribution; holders never query by private statusId",
        status_allocation_model: "dense zero-based issuer-assigned slots; snapshot size follows the allocated high-water mark",
        sparse_depth: SPARSE_STATUS_DEPTH,
        packed_depth: PACKED_STATUS_DEPTH,
        packed_statuses_per_chunk: PACKED_STATUS_BITS_PER_CHUNK,
        results,
    }
}

fn estimate_workload(workload: Workload) -> StatusDistributionWorkloadReport {
    assert!(
        workload.changed_statuses as u64 <= workload.credential_population,
        "changed statuses cannot exceed the population"
    );
    let status_slots = deterministic_status_slots(workload);

    let sparse_leaves = status_slots
        .iter()
        .map(|slot| sparse_status_index(*slot))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        sparse_leaves.len(),
        workload.changed_statuses,
        "deterministic sparse fixture unexpectedly collided"
    );
    let sparse_multiproof_siblings = multiproof_sibling_count(sparse_leaves, SPARSE_STATUS_DEPTH);
    let sparse_unbatched_delta_bytes = workload.changed_statuses as u64
        * (CHECKPOINT_TRANSITION_BYTES
            + SPARSE_INDEX_BYTES
            + FIELD_BYTES * 2
            + SPARSE_STATUS_DEPTH as u64 * FIELD_BYTES);
    let sparse_batch_patch_bytes = CHECKPOINT_TRANSITION_BYTES
        + workload.changed_statuses as u64 * (SPARSE_INDEX_BYTES + FIELD_BYTES * 2)
        + sparse_multiproof_siblings as u64 * FIELD_BYTES;

    let changed_chunks = status_slots
        .iter()
        .map(|slot| slot >> 8)
        .collect::<BTreeSet<_>>();
    let packed_multiproof_siblings =
        multiproof_sibling_count(changed_chunks.clone(), PACKED_STATUS_DEPTH);
    let packed_batch_patch_bytes = CHECKPOINT_TRANSITION_BYTES
        + changed_chunks.len() as u64 * (PACKED_CHUNK_INDEX_BYTES + FIELD_BYTES * 2)
        + packed_multiproof_siblings as u64 * FIELD_BYTES;
    let packed_full_snapshot_bytes = workload
        .credential_population
        .div_ceil(PACKED_STATUS_BITS_PER_CHUNK as u64)
        * FIELD_BYTES
        + CHECKPOINT_BYTES;
    let (selected_delivery, selected_delivery_bytes) =
        if packed_batch_patch_bytes <= packed_full_snapshot_bytes {
            (DeliveryMode::BatchPatch, packed_batch_patch_bytes)
        } else {
            (DeliveryMode::FullSnapshot, packed_full_snapshot_bytes)
        };

    StatusDistributionWorkloadReport {
        name: workload.name,
        credential_population: workload.credential_population,
        changed_statuses: workload.changed_statuses,
        sparse_merkle: SparseMerkleBatchEstimate {
            changed_leaves: workload.changed_statuses,
            multiproof_siblings: sparse_multiproof_siblings,
            holder_witness_floor_bytes: CHECKPOINT_BYTES
                + FIELD_BYTES
                + SPARSE_STATUS_DEPTH as u64 * FIELD_BYTES,
            unbatched_delta_bytes: sparse_unbatched_delta_bytes,
            batch_patch_bytes: sparse_batch_patch_bytes,
            batch_reduction_basis_points: reduction_basis_points(
                sparse_unbatched_delta_bytes,
                sparse_batch_patch_bytes,
            ),
        },
        packed_status: PackedStatusBatchEstimate {
            changed_chunks: changed_chunks.len(),
            multiproof_siblings: packed_multiproof_siblings,
            holder_witness_floor_bytes: CHECKPOINT_BYTES
                + FIELD_BYTES
                + PACKED_STATUS_DEPTH as u64 * FIELD_BYTES,
            batch_patch_bytes: packed_batch_patch_bytes,
            full_snapshot_bytes: packed_full_snapshot_bytes,
            selected_delivery,
            selected_delivery_bytes,
            reduction_vs_sparse_batch_basis_points: reduction_basis_points(
                sparse_batch_patch_bytes,
                selected_delivery_bytes,
            ),
        },
    }
}

fn deterministic_status_slots(workload: Workload) -> BTreeSet<u64> {
    let mut slots = BTreeSet::new();
    let mut counter = 0u64;
    while slots.len() < workload.changed_statuses {
        let value = mix64(
            STATUS_SEED
                ^ workload.credential_population
                ^ (workload.changed_statuses as u64).rotate_left(17)
                ^ counter,
        );
        slots.insert(value % workload.credential_population);
        counter += 1;
    }
    slots
}

fn sparse_status_index(status_slot: u64) -> u128 {
    let high = mix64(status_slot ^ STATUS_SEED) as u128;
    let low = mix64(status_slot ^ STATUS_SEED.rotate_left(29)) as u128;
    ((high << 64) | low) & ((1u128 << SPARSE_STATUS_DEPTH) - 1)
}

fn mix64(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

fn multiproof_sibling_count<T>(mut active: BTreeSet<T>, depth: usize) -> usize
where
    T: Copy + Ord + std::ops::BitXor<Output = T> + std::ops::Shr<usize, Output = T> + From<u8>,
{
    let mut siblings = 0usize;
    for _ in 0..depth {
        let mut parents = BTreeSet::new();
        for node in &active {
            if !active.contains(&(*node ^ T::from(1))) {
                siblings += 1;
            }
            parents.insert(*node >> 1);
        }
        active = parents;
    }
    siblings
}

fn reduction_basis_points(baseline: u64, candidate: u64) -> u64 {
    baseline.saturating_sub(candidate).saturating_mul(10_000) / baseline
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multiproof_counts_shared_paths_once() {
        assert_eq!(multiproof_sibling_count(BTreeSet::from([2u64]), 4), 4);
        assert_eq!(multiproof_sibling_count(BTreeSet::from([2u64, 3]), 4), 3);
        assert_eq!(multiproof_sibling_count(BTreeSet::from_iter(0u64..8), 3), 0);
    }

    #[test]
    fn workload_generation_is_deterministic_and_unique() {
        let workload = WORKLOADS[1];
        let first = deterministic_status_slots(workload);
        let second = deterministic_status_slots(workload);
        assert_eq!(first, second);
        assert_eq!(first.len(), workload.changed_statuses);
        assert!(first
            .iter()
            .all(|slot| *slot < workload.credential_population));
    }

    #[test]
    fn report_shape_and_delivery_choices_are_pinned() {
        let report = run_status_distribution_bakeoff();
        assert_eq!(report.results.len(), 3);
        assert_eq!(
            report
                .results
                .iter()
                .map(|result| result.name)
                .collect::<Vec<_>>(),
            ["regional-normal", "regional-stress", "global-stress"]
        );
        assert_eq!(
            report
                .results
                .iter()
                .map(|result| (
                    result.sparse_merkle.multiproof_siblings,
                    result.sparse_merkle.batch_patch_bytes,
                    result.packed_status.changed_chunks,
                    result.packed_status.multiproof_siblings,
                    result.packed_status.selected_delivery_bytes,
                ))
                .collect::<Vec<_>>(),
            [
                (85_123, 2_800_008, 1_000, 7_674, 312_640),
                (7_850_028, 258_800_968, 88_279, 143_616, 10_510_477),
                (7_850_061, 258_802_024, 98_756, 443_963, 20_823_540),
            ],
            "distribution-model drift requires an explicit report review"
        );
        assert!(report.results.iter().all(|result| {
            result.packed_status.selected_delivery == DeliveryMode::BatchPatch
                && result.sparse_merkle.batch_patch_bytes
                    < result.sparse_merkle.unbatched_delta_bytes
                && result.packed_status.selected_delivery_bytes
                    < result.sparse_merkle.batch_patch_bytes
        }));
    }

    #[test]
    fn a_dense_incident_switches_to_the_smaller_snapshot() {
        let report = estimate_workload(Workload {
            name: "dense-fixture",
            credential_population: 65_536,
            changed_statuses: 65_536,
        });
        assert_eq!(report.packed_status.changed_chunks, 256);
        assert_eq!(
            report.packed_status.selected_delivery,
            DeliveryMode::FullSnapshot
        );
        assert_eq!(report.packed_status.selected_delivery_bytes, 8_228);
        assert!(report.packed_status.full_snapshot_bytes < report.packed_status.batch_patch_bytes);
    }
}
