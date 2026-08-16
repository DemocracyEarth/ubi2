// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script, console2} from "forge-std/Script.sol";
import {ZkIdentityIssuanceRegistry} from "../src/ZkIdentityIssuanceRegistry.sol";
import {ZkIdentitySelfIssuanceBridge} from "../src/ZkIdentitySelfIssuanceBridge.sol";

/// @title Testnet deployment of the v2 issuance registry and immutable Self bridge
/// @dev This script never reads a private key. Use an encrypted Foundry account.
///      The verifier configuration id must be computed from the exact public
///      Self scope, endpoint, environment, attestation id and verifier version.
contract DeployZkSelfIssuance is Script {
    function run() external {
        require(supportedTestnet(block.chainid), "unsupported chain: testnets only");
        bytes32 issuerKeyId = vm.envBytes32("ZK_ISSUER_KEY_ID");
        address verificationAuthority = vm.envAddress("ZK_SELF_VERIFICATION_AUTHORITY");
        bytes32 selfConfigId = vm.envBytes32("ZK_SELF_CONFIG_ID");
        require(issuerKeyId != bytes32(0), "ZK_ISSUER_KEY_ID unset");
        require(verificationAuthority != address(0), "ZK_SELF_VERIFICATION_AUTHORITY unset");
        require(selfConfigId != bytes32(0), "ZK_SELF_CONFIG_ID unset");

        vm.startBroadcast();
        (, address deployer,) = vm.readCallers();
        address finalOwner = vm.envOr("ZK_ISSUANCE_OWNER", deployer);
        require(finalOwner != address(0), "ZK_ISSUANCE_OWNER zero");

        ZkIdentityIssuanceRegistry registry = new ZkIdentityIssuanceRegistry(deployer);
        registry.registerIssuerKey(issuerKeyId);
        ZkIdentitySelfIssuanceBridge bridge =
            new ZkIdentitySelfIssuanceBridge(registry, issuerKeyId, verificationAuthority, selfConfigId);
        registry.authorizeIssuanceAuthority(issuerKeyId, address(bridge));
        if (finalOwner != deployer) registry.transferOwnership(finalOwner);
        vm.stopBroadcast();

        console2.log("chainid                    :", block.chainid);
        console2.log("ZkIdentityIssuanceRegistry:", address(registry));
        console2.logBytes32(registry.issuanceDomain());
        console2.log("ZkIdentitySelfIssuanceBridge:", address(bridge));
        console2.logBytes32(issuerKeyId);
        console2.log("verification authority     :", verificationAuthority);
        console2.logBytes32(selfConfigId);
        console2.log("registry current owner      :", registry.owner());
        console2.log("registry pending owner      :", registry.pendingOwner());
    }

    function supportedTestnet(uint256 chainId) public pure returns (bool) {
        return chainId == 31_337 || chainId == 84_532 || chainId == 11_155_111 || chainId == 11_142_220
            || chainId == 46_630 || chainId == 4_801;
    }
}
