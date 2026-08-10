// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {StdInvariant} from "forge-std/StdInvariant.sol";
import {ProofOfHumanity, HumanityVoucher} from "../src/ProofOfHumanity.sol";

contract ProofOfHumanityHandler is Test {
    ProofOfHumanity internal immutable POH;

    uint256 internal constant ISSUER_PK = 0xA11CE;

    mapping(uint256 nullifier => address wallet) public walletOf;
    mapping(uint256 nullifier => uint256 tokenId) public expectedTokenOf;
    mapping(uint256 nullifier => uint32 epoch) public lastEpochOf;
    uint256[] internal _nullifiers;

    constructor(ProofOfHumanity poh_) {
        POH = poh_;
    }

    function mintOrRefresh(uint256 nullifier, address candidateWallet, uint16 epochStep) external {
        address wallet = walletOf[nullifier];
        bool isNew = wallet == address(0);
        if (isNew) {
            wallet = candidateWallet == address(0) ? address(1) : candidateWallet;
            walletOf[nullifier] = wallet;
        }

        uint32 epoch = isNew ? POH.currentEpoch() : lastEpochOf[nullifier] + uint32(bound(epochStep, 1, 32));
        HumanityVoucher memory voucher = HumanityVoucher({to: wallet, nullifier: nullifier, epoch: epoch});
        uint256 tokenId = POH.mintWithVoucher(voucher, _sign(voucher));

        if (isNew) {
            expectedTokenOf[nullifier] = tokenId;
            _nullifiers.push(nullifier);
        } else {
            assertEq(tokenId, expectedTokenOf[nullifier], "refresh allocated a second token");
        }
        lastEpochOf[nullifier] = epoch;
    }

    function attemptSecondWallet(uint256 nullifier, address candidateWallet) external {
        address originalWallet = walletOf[nullifier];
        if (originalWallet == address(0)) return;

        address otherWallet = candidateWallet;
        if (otherWallet == address(0) || otherWallet == originalWallet) {
            otherWallet = originalWallet == address(1) ? address(2) : address(1);
        }

        HumanityVoucher memory voucher =
            HumanityVoucher({to: otherWallet, nullifier: nullifier, epoch: lastEpochOf[nullifier] + 1});
        bytes memory signature = _sign(voucher);
        vm.expectRevert(ProofOfHumanity.NullifierOwnerMismatch.selector);
        POH.mintWithVoucher(voucher, signature);
    }

    function trackedCount() external view returns (uint256) {
        return _nullifiers.length;
    }

    function trackedNullifier(uint256 index) external view returns (uint256) {
        return _nullifiers[index];
    }

    function _sign(HumanityVoucher memory voucher) private view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ISSUER_PK, POH.hashVoucher(voucher));
        return abi.encodePacked(r, s, v);
    }
}

contract ProofOfHumanityInvariantTest is StdInvariant, Test {
    ProofOfHumanity internal poh;
    ProofOfHumanityHandler internal handler;

    uint256 internal constant ISSUER_PK = 0xA11CE;

    function setUp() public {
        vm.warp(1_700_000_000);
        poh = new ProofOfHumanity(address(this), vm.addr(ISSUER_PK));
        handler = new ProofOfHumanityHandler(poh);

        bytes4[] memory selectors = new bytes4[](2);
        selectors[0] = handler.mintOrRefresh.selector;
        selectors[1] = handler.attemptSecondWallet.selector;
        targetContract(address(handler));
        targetSelector(FuzzSelector({addr: address(handler), selectors: selectors}));
        excludeContract(address(poh));
    }

    function invariant_EachNullifierAlwaysMapsToItsFirstToken() public view {
        uint256 count = handler.trackedCount();
        for (uint256 i = 0; i < count; i++) {
            uint256 nullifier = handler.trackedNullifier(i);
            uint256 expectedToken = handler.expectedTokenOf(nullifier);
            assertTrue(expectedToken != 0);
            assertEq(poh.tokenOfNullifier(nullifier), expectedToken);
            assertEq(poh.ownerOf(expectedToken), handler.walletOf(nullifier));
        }
    }

    function invariant_DistinctNullifiersNeverShareAToken() public view {
        uint256 count = handler.trackedCount();
        for (uint256 i = 0; i < count; i++) {
            uint256 tokenA = handler.expectedTokenOf(handler.trackedNullifier(i));
            for (uint256 j = i + 1; j < count; j++) {
                uint256 tokenB = handler.expectedTokenOf(handler.trackedNullifier(j));
                assertNotEq(tokenA, tokenB);
            }
        }
    }

    function invariant_NextIdCountsOnlyUniqueNullifiers() public view {
        assertEq(poh.nextId(), handler.trackedCount() + 1);
    }
}
