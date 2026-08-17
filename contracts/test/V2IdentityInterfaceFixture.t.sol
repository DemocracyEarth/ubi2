// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {ZkIdentityEncoding} from "../src/ZkIdentityEncoding.sol";

contract V2IdentityInterfaceFixtureHarness {
    function privateCredentialFingerprint(ZkIdentityEncoding.PrivateCredential memory credential)
        external
        pure
        returns (bytes32)
    {
        return ZkIdentityEncoding.privateCredentialFingerprint(credential);
    }

    function issuanceDomainHash(uint256 chainId, address registry) external pure returns (bytes32) {
        return ZkIdentityEncoding.issuanceDomainHash(chainId, registry);
    }

    function nullifierScopeHash(ZkIdentityEncoding.NullifierScope memory scope) external pure returns (bytes32) {
        return ZkIdentityEncoding.nullifierScopeHash(scope);
    }

    function scopedNullifierPreimage(uint256 holderSecret, ZkIdentityEncoding.NullifierScope memory scope)
        external
        pure
        returns (uint256[6] memory)
    {
        return ZkIdentityEncoding.scopedNullifierPreimage(holderSecret, scope);
    }

    function decodePublicSignals(uint256[] memory signals)
        external
        pure
        returns (ZkIdentityEncoding.PublicSignals memory)
    {
        return ZkIdentityEncoding.decodePublicSignals(signals);
    }
}

/// @notice Release-owned compatibility gate consumed by SDK and Rust tests too.
contract V2IdentityInterfaceFixtureTest is Test {
    using stdJson for string;

    string internal fixture;
    V2IdentityInterfaceFixtureHarness internal harness;

    function setUp() public {
        fixture = vm.readFile(string.concat(vm.projectRoot(), "/../fixtures/v2-identity/interface-v1.json"));
        harness = new V2IdentityInterfaceFixtureHarness();
    }

    function test_SharedFixtureRecomputesFrozenBoundaries() public view {
        assertEq(fixture.readString(".schema"), "org.proofofhumanity.v2-cross-lane-interface/1");
        assertEq(fixture.readString(".classification.productionCryptography"), "unratified");

        ZkIdentityEncoding.PrivateCredential memory credential = ZkIdentityEncoding.PrivateCredential({
            issuerKeyId: fixture.readBytes32(".privateCredential.issuerKeyId"),
            statusId: fixture.readBytes32(".privateCredential.statusId"),
            holderSecret: vm.parseUint(fixture.readString(".privateCredential.holderSecret")),
            credentialBlinding: vm.parseUint(fixture.readString(".privateCredential.credentialBlinding")),
            dateOfBirth: _date(fixture.readString(".privateCredential.dateOfBirth")),
            nationality: _bytes3(fixture.readString(".privateCredential.nationality")),
            issuingState: _bytes3(fixture.readString(".privateCredential.issuingState")),
            expiryDate: _date(fixture.readString(".privateCredential.expiryDate")),
            documentClass: 1,
            assurance: 2,
            issuedAtEpoch: uint32(fixture.readUint(".privateCredential.issuedAtEpoch"))
        });
        assertEq(
            harness.privateCredentialFingerprint(credential),
            fixture.readBytes32(".privateCredential.diagnosticFingerprint")
        );
        assertEq(
            harness.issuanceDomainHash(
                fixture.readUint(".issuanceDomain.chainId"), fixture.readAddress(".issuanceDomain.registry")
            ),
            fixture.readBytes32(".issuanceDomain.hash")
        );

        ZkIdentityEncoding.NullifierScope memory scope = _scope();
        assertEq(harness.nullifierScopeHash(scope), fixture.readBytes32(".nullifierScope.hash"));
        uint256[6] memory preimage = harness.scopedNullifierPreimage(credential.holderSecret, scope);
        string[] memory expectedPreimage = fixture.readStringArray(".nullifierScope.preimage");
        assertEq(expectedPreimage.length, preimage.length);
        for (uint256 i = 0; i < preimage.length; ++i) {
            assertEq(preimage[i], vm.parseUint(expectedPreimage[i]));
        }

        ZkIdentityEncoding.PublicSignals memory decoded = harness.decodePublicSignals(_signals());
        assertEq(decoded.circuitId, fixture.readBytes32(".publicSignals.semanticValues.circuitId"));
        assertEq(decoded.issuerKeyId, fixture.readBytes32(".publicSignals.semanticValues.issuerKeyId"));
        assertEq(decoded.activeRoot, fixture.readBytes32(".publicSignals.semanticValues.activeRoot"));
        assertEq(decoded.policyHash, fixture.readBytes32(".publicSignals.semanticValues.policyHash"));
        assertEq(
            decoded.presentationBindingHash,
            fixture.readBytes32(".publicSignals.semanticValues.presentationBindingHash")
        );
        assertEq(decoded.nullifierScopeHash, fixture.readBytes32(".publicSignals.semanticValues.nullifierScopeHash"));
        assertEq(
            decoded.scopedNullifier, vm.parseUint(fixture.readString(".publicSignals.semanticValues.scopedNullifier"))
        );
        assertEq(decoded.subject, fixture.readAddress(".publicSignals.semanticValues.subject"));
        assertEq(decoded.result, fixture.readBool(".publicSignals.semanticValues.result"));
        assertEq(decoded.credentialEpoch, fixture.readUint(".publicSignals.semanticValues.credentialEpoch"));
        assertEq(decoded.statusEpoch, fixture.readUint(".publicSignals.semanticValues.statusEpoch"));
    }

    function test_SharedFixtureMutationsFailClosed() public {
        uint256[] memory values = _mutatedSignals(0, "unsupported-layout");
        vm.expectRevert(ZkIdentityEncoding.UnsupportedPublicSignalLayout.selector);
        harness.decodePublicSignals(values);

        values = _mutatedSignals(1, "zero-policy-hash");
        vm.expectRevert(abi.encodeWithSelector(ZkIdentityEncoding.InvalidIdentifier.selector, 7));
        harness.decodePublicSignals(values);

        values = _mutatedSignals(2, "noncanonical-nullifier");
        vm.expectRevert(abi.encodeWithSelector(ZkIdentityEncoding.NonCanonicalField.selector, 13));
        harness.decodePublicSignals(values);

        values = _mutatedSignals(3, "zero-subject");
        vm.expectRevert(ZkIdentityEncoding.InvalidSubject.selector);
        harness.decodePublicSignals(values);

        values = _mutatedSignals(4, "nonboolean-result");
        vm.expectRevert(ZkIdentityEncoding.InvalidResult.selector);
        harness.decodePublicSignals(values);
    }

    function _scope() internal view returns (ZkIdentityEncoding.NullifierScope memory) {
        return ZkIdentityEncoding.NullifierScope({
            mode: 1,
            chainId: fixture.readUint(".nullifierScope.chainId"),
            verifier: fixture.readAddress(".nullifierScope.verifier"),
            consumer: fixture.readAddress(".nullifierScope.consumer"),
            context: fixture.readBytes32(".nullifierScope.context"),
            policyHash: fixture.readBytes32(".nullifierScope.policyHash")
        });
    }

    function _signals() internal view returns (uint256[] memory values) {
        string[] memory encoded = fixture.readStringArray(".publicSignals.values");
        values = new uint256[](encoded.length);
        for (uint256 i = 0; i < encoded.length; ++i) {
            values[i] = vm.parseUint(encoded[i]);
        }
    }

    function _mutatedSignals(uint256 fixtureIndex, string memory expectedName)
        internal
        view
        returns (uint256[] memory values)
    {
        string memory path = string.concat(".negativeMutations[", vm.toString(fixtureIndex), "]");
        assertEq(fixture.readString(string.concat(path, ".name")), expectedName);
        values = _signals();
        values[fixture.readUint(string.concat(path, ".index"))] =
            vm.parseUint(fixture.readString(string.concat(path, ".value")));
        if (fixtureIndex == 1) {
            values[fixture.readUint(string.concat(path, ".alsoIndex"))] =
                vm.parseUint(fixture.readString(string.concat(path, ".alsoValue")));
        }
    }

    function _bytes3(string memory value) internal pure returns (bytes3 result) {
        bytes memory encoded = bytes(value);
        require(encoded.length == 3, "fixture country code must be bytes3");
        assembly ("memory-safe") {
            result := mload(add(encoded, 0x20))
        }
    }

    function _date(string memory value) internal pure returns (uint32 parsed) {
        bytes memory encoded = bytes(value);
        require(encoded.length == 10 && encoded[4] == "-" && encoded[7] == "-", "fixture date must be YYYY-MM-DD");
        for (uint256 i = 0; i < encoded.length; ++i) {
            if (i == 4 || i == 7) continue;
            require(encoded[i] >= "0" && encoded[i] <= "9", "fixture date contains a non-digit");
            parsed = parsed * 10 + uint8(encoded[i]) - 48;
        }
    }
}
