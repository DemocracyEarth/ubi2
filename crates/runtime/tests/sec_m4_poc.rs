//! GATE 3 (M4 security) red-team PoCs against the prompt-contract escrow/authority boundary.
//! These are *probes*: some assert the boundary HOLDS (regression guards), some demonstrate a
//! finding. Named distinctly to avoid colliding with other gates.

use ubi2_runtime::lifecycle::register_juror;
use ubi2_runtime::{
    apply_transfer, contract_address, deploy_contract, fund_contract, invoke_contract,
    CanonicalEffect, ContractError, ContractId, ExecCaseId, ExecStatus, MemState, MockInterpreter,
    Op, State, UBI,
};

fn addr(b: u8) -> [u8; 20] {
    [b; 20]
}

/// Deploy a contract from a 32-byte ref (M4: the full text now lives on-chain). The text is a
/// deterministic stand-in derived from the ref; the runtime stores both `text` + `text_ref`.
fn deploy_c(s: &mut MemState, text_ref: [u8; 32], parties: Vec<[u8; 20]>) -> ContractId {
    let text = format!("poc-contract:{}", text_ref[0]);
    deploy_contract(s, text, text_ref, parties).unwrap()
}

/// Invoke a contract. The interpreter now reads the contract's stored text, so the old `_text` arg is
/// ignored; a fixed resolving `block` of `1` is threaded in for the offline PoCs.
#[allow(clippy::too_many_arguments)]
fn invoke_c(
    s: &mut MemState,
    interp: &MockInterpreter,
    id: ContractId,
    _text: &[u8],
    trigger_ref: [u8; 32],
    trigger: &[u8],
    invoker: [u8; 20],
    entropy: u64,
    now: u64,
) -> Result<ExecCaseId, ContractError> {
    invoke_contract(
        s,
        interp,
        id,
        trigger_ref,
        trigger,
        invoker,
        entropy,
        1,
        now,
    )
}

fn interpreters(s: &mut MemState, n: u8) {
    for i in 0..n {
        register_juror(s, &addr(100 + i), 0);
    }
}

fn seed(s: &mut MemState, a: [u8; 20], bal: u128) {
    s.put(ubi2_runtime::Account {
        address: a,
        verified: true,
        verified_at: 0,
        last_settled_at: 0,
        settled_balance: bal,
        nonce: 0,
    });
}

/// PROBE 1 — A committed Transfer can only ever move escrow to its target, never to a third
/// account, and can never exceed escrow. (Authority boundary holds.)
#[test]
fn transfer_cannot_exceed_escrow_or_touch_third_account() {
    let mut s = MemState::new();
    interpreters(&mut s, 3);
    let funder = addr(1);
    let payee = addr(2);
    let victim = addr(9);
    seed(&mut s, funder, 100 * UBI);
    seed(&mut s, victim, 50 * UBI); // an unrelated account
    let id = deploy_c(&mut s, [9u8; 32], vec![funder, payee]);
    fund_contract(&mut s, &funder, id, 5 * UBI, 0, 0).unwrap();

    // Try to move 6 UBI (> 5 escrow) ⇒ abort, no state change.
    let interp = MockInterpreter::always(CanonicalEffect::new(vec![Op::Transfer {
        to: payee,
        amount: 6 * UBI,
    }]));
    let case = invoke_c(&mut s, &interp, id, b"t", [0u8; 32], b"x", funder, 1, 0).unwrap();
    assert_eq!(s.get_exec_case(case).unwrap().status, ExecStatus::Aborted);
    // Victim account is untouched and escrow intact.
    assert_eq!(s.balance(&victim, 0), 50 * UBI);
    assert_eq!(s.get_contract(id).unwrap().escrow, 5 * UBI);
}

/// PROBE 2 (FINDING CANDIDATE) — a plain value transfer sent directly to the contract's escrow
/// ADDRESS raises the escrow account balance but NOT the tracked `contract.escrow`. Does this let a
/// later effect over-draw the escrow account? And are the directly-sent funds recoverable?
#[test]
fn direct_transfer_to_escrow_desyncs_accounting() {
    let mut s = MemState::new();
    interpreters(&mut s, 3);
    let funder = addr(1);
    let payee = addr(2);
    seed(&mut s, funder, 100 * UBI);
    let id = deploy_c(&mut s, [9u8; 32], vec![funder, payee]);
    let escrow = contract_address(id);

    // Proper funding of 3 UBI via fundContract.
    fund_contract(&mut s, &funder, id, 3 * UBI, 0, 0).unwrap();
    assert_eq!(s.get_contract(id).unwrap().escrow, 3 * UBI);
    assert_eq!(s.balance(&escrow, 0), 3 * UBI);

    // Now a plain value transfer of 4 UBI sent DIRECTLY to the escrow address (NOT fundContract).
    apply_transfer(&mut s, &funder, &escrow, 4 * UBI, 1, 0).unwrap();
    // The escrow ACCOUNT now holds 7 UBI, but the tracked contract.escrow is still 3 UBI.
    assert_eq!(s.balance(&escrow, 0), 7 * UBI);
    assert_eq!(s.get_contract(id).unwrap().escrow, 3 * UBI);

    // Can the contract move the extra 4? Validation is against contract.escrow (3), so an effect for
    // 5 UBI is rejected even though the account holds 7. So the contract is BOUNDED BELOW the account
    // balance — the directly-sent 4 UBI is STRANDED (no effect can ever release it; it's not a party
    // refund either since the funds aren't tracked). Security-wise: not theft, but a fund-loss trap.
    let interp = MockInterpreter::always(CanonicalEffect::new(vec![Op::Transfer {
        to: payee,
        amount: 5 * UBI,
    }]));
    let case = invoke_c(&mut s, &interp, id, b"t", [0u8; 32], b"x", funder, 2, 0).unwrap();
    assert_eq!(
        s.get_exec_case(case).unwrap().status,
        ExecStatus::Aborted,
        "over-draw vs tracked escrow rejected (good)"
    );

    // Drain the full tracked escrow (3 UBI). The account is left holding the stranded 4 UBI forever:
    // contract.escrow goes to 0, but balance(escrow) stays 4. No op can target it.
    let drain = MockInterpreter::always(CanonicalEffect::new(vec![Op::Transfer {
        to: payee,
        amount: 3 * UBI,
    }]));
    invoke_c(&mut s, &drain, id, b"t", [0u8; 32], b"y", funder, 3, 0).unwrap();
    assert_eq!(s.get_contract(id).unwrap().escrow, 0);
    assert_eq!(
        s.balance(&escrow, 0),
        4 * UBI,
        "FINDING: 4 UBI stranded in the escrow account, unrecoverable"
    );
}

/// PROBE 3 (CONSENSUS-HALT CANDIDATE) — can `contract.escrow` ever exceed the escrow ACCOUNT
/// balance? If so, Phase 2 of apply_effect calls apply_transfer with escrow>=draw validated against
/// contract.escrow, but the ACCOUNT lacks the balance ⇒ the `.expect()` panics (a node crash /
/// consensus halt). We try to engineer a desync where the account is drained out from under the
/// tracked escrow.
#[test]
fn escrow_account_cannot_be_drained_below_tracked_escrow() {
    let mut s = MemState::new();
    interpreters(&mut s, 3);
    let funder = addr(1);
    let payee = addr(2);
    seed(&mut s, funder, 100 * UBI);
    let id = deploy_c(&mut s, [9u8; 32], vec![funder, payee]);
    let escrow = contract_address(id);
    fund_contract(&mut s, &funder, id, 10 * UBI, 0, 0).unwrap();

    // The escrow address is a normal account. Its nonce starts at 0. Could an attacker forge a
    // transfer FROM the escrow account to drain it? They'd need the escrow account's private key,
    // which is a derived address with (almost certainly) no known key — but the runtime
    // apply_transfer takes `from` by value with no signature check at THIS layer (the RPC layer does
    // EIP-155 recovery). At the runtime layer, simulate a transfer FROM escrow draining it:
    let pre = s.balance(&escrow, 0);
    assert_eq!(pre, 10 * UBI);
    // If such a drain were possible at the RPC layer (it is not, absent the key), contract.escrow
    // (10) would exceed the account balance and the next effect's Phase-2 apply_transfer would panic.
    // Confirm the apply path's invariant holds when accounting is consistent:
    let interp = MockInterpreter::always(CanonicalEffect::new(vec![Op::Transfer {
        to: payee,
        amount: 10 * UBI,
    }]));
    let case = invoke_c(&mut s, &interp, id, b"t", [0u8; 32], b"x", funder, 1, 0).unwrap();
    assert_eq!(
        s.get_exec_case(case).unwrap().status,
        ExecStatus::Committed(CanonicalEffect::new(vec![Op::Transfer {
            to: payee,
            amount: 10 * UBI
        }]))
    );
    assert_eq!(s.balance(&payee, 0), 10 * UBI);
    assert_eq!(s.get_contract(id).unwrap().escrow, 0);
}

/// PROBE 4 — re-invocation does NOT replay a prior committed effect: each invoke opens a fresh
/// ExecCase and validates against the CURRENT escrow, so a drained escrow can't pay twice.
#[test]
fn reinvocation_cannot_replay_a_committed_effect() {
    let mut s = MemState::new();
    interpreters(&mut s, 3);
    let funder = addr(1);
    let payee = addr(2);
    seed(&mut s, funder, 100 * UBI);
    let id = deploy_c(&mut s, [9u8; 32], vec![funder, payee]);
    fund_contract(&mut s, &funder, id, 5 * UBI, 0, 0).unwrap();

    let interp = MockInterpreter::always(CanonicalEffect::new(vec![Op::Transfer {
        to: payee,
        amount: 5 * UBI,
    }]));
    // First invoke pays 5 UBI.
    invoke_c(&mut s, &interp, id, b"t", [0u8; 32], b"x", funder, 1, 0).unwrap();
    assert_eq!(s.balance(&payee, 0), 5 * UBI);
    assert_eq!(s.get_contract(id).unwrap().escrow, 0);

    // Second invoke of the SAME effect: escrow is now 0 ⇒ over-draw ⇒ abort, NOT a second payment.
    let case2 = invoke_c(&mut s, &interp, id, b"t", [0u8; 32], b"x2", funder, 2, 0).unwrap();
    assert_eq!(s.get_exec_case(case2).unwrap().status, ExecStatus::Aborted);
    assert_eq!(s.balance(&payee, 0), 5 * UBI, "no double payment");
}

/// PROBE 5 — a contract cannot StopStream a stream owned by a DIFFERENT contract's escrow (or any
/// other account) — least authority on streams.
#[test]
fn cannot_stop_a_stream_owned_by_another_contract() {
    let mut s = MemState::new();
    interpreters(&mut s, 3);
    let funder = addr(1);
    let bob = addr(2);
    seed(&mut s, funder, 1_000 * UBI);

    // Contract A opens a stream from its own escrow.
    let a = deploy_c(&mut s, [1u8; 32], vec![funder, bob]);
    let hour = 3600u128;
    fund_contract(&mut s, &funder, a, 10 * hour, 0, 0).unwrap();
    let open = MockInterpreter::always(CanonicalEffect::new(vec![Op::OpenStream {
        to: bob,
        rate: 1,
        deposit: 10 * hour,
    }]));
    invoke_c(&mut s, &open, a, b"s", [0u8; 32], b"open", funder, 1, 0).unwrap();
    let a_escrow = contract_address(a);
    let victim_stream = s.outgoing(&a_escrow)[0];

    // Contract B tries to StopStream A's stream (to steal the refund into B's escrow).
    let b = deploy_c(&mut s, [2u8; 32], vec![funder]);
    fund_contract(&mut s, &funder, b, UBI, 1, 0).unwrap();
    let steal = MockInterpreter::always(CanonicalEffect::new(vec![Op::StopStream {
        id: victim_stream,
    }]));
    let case = invoke_c(&mut s, &steal, b, b"s", [0u8; 32], b"steal", funder, 2, 0).unwrap();
    assert_eq!(
        s.get_exec_case(case).unwrap().status,
        ExecStatus::Aborted,
        "B must not be able to stop A's stream (least authority)"
    );
    // A's stream is still live and owned by A.
    assert_eq!(s.outgoing(&a_escrow), vec![victim_stream]);
}

/// PROBE 6 — escrow address derivation is collision-free with a normal EOA in the relevant id range
/// and distinct per id (no two contracts share an escrow).
#[test]
fn escrow_addresses_are_distinct_and_tagged() {
    let a0 = contract_address(0);
    let a1 = contract_address(1);
    let big = contract_address(u64::MAX);
    assert_ne!(a0, a1);
    assert_ne!(a1, big);
    // All carry the 'PC' tag at bytes 10..12 (the ContractHub marker) so they live in a reserved
    // space an ordinary low-numbered EOA (e.g. the dev account 0x..01) does not occupy.
    for a in [a0, a1, big] {
        assert_eq!(&a[10..12], &[0x50, 0x43]);
    }
}
