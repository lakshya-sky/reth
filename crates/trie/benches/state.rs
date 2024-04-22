#![allow(missing_docs, unreachable_pub)]
use criterion::{
    black_box, criterion_group, criterion_main, measurement::WallTime, BenchmarkGroup, Criterion,
};
use proptest::{
    prelude::*,
    strategy::ValueTree,
    test_runner::{basic_result_cache, TestRunner},
};
use reth_primitives::{revm::compat::into_revm_acc, Account, Address, U256};
use reth_trie::HashedPostState;
use revm::{
    db::{AccountStatus, BundleAccount},
    primitives::StorageSlot,
};
use std::collections::HashMap;

pub fn state_lookups(c: &mut Criterion) {
    rayon::ThreadPoolBuilder::new().num_threads(2).build_global().unwrap();
    let mut group = c.benchmark_group("from_bundle_state");
    for size in [4, 8, 16, 32, 64, 96, 128, 256, 512, 1024, 4096] {
        let test_data = generate_test_data(size);
        println!("threads: {}, size: {}", rayon::current_num_threads(), size);
        state_bench(&mut group, &test_data);
    }
}

fn state_bench(group: &mut BenchmarkGroup<'_, WallTime>, input: &HashMap<Address, BundleAccount>) {
    let group_id = format!("input size: {}", input.len());

    let setup = move || {
        HashedPostState::from_bundle_state(&input);
    };

    group.bench_function(group_id, |b| {
        b.iter(|| {
            let _ = black_box(setup());
        });
    });
}

fn generate_test_data(size: usize) -> HashMap<Address, BundleAccount> {
    use prop::collection::vec;

    let config = ProptestConfig { result_cache: basic_result_cache, ..Default::default() };
    let mut runner = TestRunner::new(config);

    let mut addresses = vec(any::<Address>(), size).new_tree(&mut runner).unwrap().current();
    addresses.dedup();

    let vec_status = (0..size).map(|_| {
        let x = rand::thread_rng().gen_range(0..8);
        match x {
            0 => AccountStatus::LoadedNotExisting,
            1 => AccountStatus::Loaded,
            2 => AccountStatus::LoadedEmptyEIP161,
            3 => AccountStatus::InMemoryChange,
            4 => AccountStatus::Changed,
            5 => AccountStatus::Destroyed,
            6 => AccountStatus::DestroyedChanged,
            _ => AccountStatus::DestroyedAgain,
        }
    });

    let present_info_vec = vec(any::<Account>(), size)
        .new_tree(&mut runner)
        .unwrap()
        .current()
        .into_iter()
        .map(into_revm_acc);

    addresses
        .into_iter()
        .zip(present_info_vec)
        .zip(vec_status)
        .map(|((address, present_account), status)| {
            let mut map = HashMap::new();
            for slot in vec(any::<(U256, U256)>(), rand::thread_rng().gen_range(4..=8))
                .new_tree(&mut runner)
                .unwrap()
                .current()
            {
                map.insert(
                    slot.0,
                    StorageSlot { previous_or_original_value: U256::ZERO, present_value: slot.1 },
                );
            }
            let account = BundleAccount::new(None, Some(present_account), map, status);
            (address, account)
        })
        .collect()
}

criterion_group!(state, state_lookups);
criterion_main!(state);
