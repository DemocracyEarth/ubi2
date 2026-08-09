// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script, console2} from "forge-std/Script.sol";
import {ProofOfHumanity} from "../src/ProofOfHumanity.sol";
import {PoHCardRenderer} from "../src/PoHCardRenderer.sol";
import {PredicateVerifier} from "../src/PredicateVerifier.sol";

/// @title Deploy — Proof of Humanity stack (any EVM chain)
/// @notice Deploys {PoHCardRenderer} + {ProofOfHumanity} (and optionally
///         {PredicateVerifier}) and wires the on-chain card renderer. The same
///         bytecode is deployed identically on every chain (Base, Ethereum, Celo,
///         …); each gets its own EIP-712 domain via its chainId + address.
///
/// Environment:
///   POH_ISSUER        (required) address whose key signs mint vouchers off-chain.
///                     MUST equal the app's ISSUER_PRIVATE_KEY address.
///   POH_OWNER         (optional) final owner that can rotate issuer/renderer;
///                     defaults to the broadcasting deployer. Recommend a multisig.
///   DEPLOY_PREDICATE  (optional) "true" to also deploy PredicateVerifier.
///
/// Run (see .claude/skills/deploy-poh-contracts/SKILL.md for full per-chain steps):
///   forge script script/Deploy.s.sol:Deploy \
///     --rpc-url "$RPC_URL" --account poh-deployer --broadcast --verify
contract Deploy is Script {
    function run() external {
        address issuer = vm.envAddress("POH_ISSUER");
        require(issuer != address(0), "POH_ISSUER unset");

        vm.startBroadcast();
        address deployer = msg.sender;
        address finalOwner = vm.envOr("POH_OWNER", deployer);
        bool withPredicate = vm.envOr("DEPLOY_PREDICATE", false);

        // Stateless SVG renderer (no constructor args, no library linking —
        // Countries is an internal library, inlined at compile time).
        PoHCardRenderer renderer = new PoHCardRenderer();

        // Own it as the deployer first so we can wire the renderer, then hand off.
        ProofOfHumanity poh = new ProofOfHumanity(deployer, issuer);
        poh.setCardRenderer(address(renderer));
        if (finalOwner != deployer) {
            poh.transferOwnership(finalOwner);
        }

        PredicateVerifier pv;
        if (withPredicate) {
            pv = new PredicateVerifier(finalOwner, issuer);
        }
        vm.stopBroadcast();

        console2.log("chainid           :", block.chainid);
        console2.log("PoHCardRenderer   :", address(renderer));
        console2.log("ProofOfHumanity   :", address(poh));
        console2.log("  owner           :", finalOwner);
        console2.log("  issuer          :", issuer);
        if (withPredicate) {
            console2.log("PredicateVerifier :", address(pv));
        }
    }
}
