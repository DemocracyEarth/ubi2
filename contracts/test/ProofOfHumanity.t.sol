// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {ProofOfHumanity, HumanityVoucher, IERC5192} from "../src/ProofOfHumanity.sol";

contract ProofOfHumanityTest is Test {
    ProofOfHumanity internal poh;

    // Issuer key pair (known private key => real EIP-712 signatures via vm.sign).
    uint256 internal constant ISSUER_PK = 0xA11CE;
    uint256 internal constant NEW_ISSUER_PK = 0xB0B;
    address internal issuer;
    address internal newIssuer;

    address internal owner;
    address internal alice;
    address internal bob;
    address internal relayer;

    // Distinct nullifiers (unrelated to token ids to avoid confusion).
    uint256 internal constant NULL_A = uint256(keccak256("nullifier-a"));
    uint256 internal constant NULL_B = uint256(keccak256("nullifier-b"));

    // 90-day epoch mirrored from the contract.
    uint256 internal constant EPOCH = 90 days;

    function setUp() public {
        issuer = vm.addr(ISSUER_PK);
        newIssuer = vm.addr(NEW_ISSUER_PK);
        owner = makeAddr("owner");
        alice = makeAddr("alice");
        bob = makeAddr("bob");
        relayer = makeAddr("relayer");

        vm.warp(1_700_000_000); // realistic block time so epochs are meaningful
        poh = new ProofOfHumanity(owner, issuer);
    }

    /*//////////////////////////////////////////////////////////////
                            HELPERS
    //////////////////////////////////////////////////////////////*/

    function _defaultVoucher(address to, uint256 nullifier) internal view returns (HumanityVoucher memory) {
        return HumanityVoucher({to: to, nullifier: nullifier, epoch: poh.currentEpoch()});
    }

    function _sign(uint256 pk, HumanityVoucher memory v) internal view returns (bytes memory) {
        bytes32 digest = poh.hashVoucher(v);
        (uint8 vv, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, vv);
    }

    function _mint(uint256 pk, HumanityVoucher memory v) internal returns (uint256) {
        bytes memory sig = _sign(pk, v);
        vm.prank(relayer);
        return poh.mintWithVoucher(v, sig);
    }

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR / ADMIN
    //////////////////////////////////////////////////////////////*/

    function test_Constructor_SetsMetadataOwnerIssuer() public view {
        assertEq(poh.name(), "Proof of Humanity");
        assertEq(poh.symbol(), "POH");
        assertEq(poh.owner(), owner);
        assertEq(poh.issuer(), issuer);
        assertEq(poh.nextId(), 1);
    }

    function test_Constructor_RevertsOnZeroIssuer() public {
        vm.expectRevert(ProofOfHumanity.InvalidIssuer.selector);
        new ProofOfHumanity(owner, address(0));
    }

    function test_SetIssuer_OnlyOwner() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSignature("OwnableUnauthorizedAccount(address)", alice));
        poh.setIssuer(newIssuer);
    }

    function test_SetIssuer_RevertsOnZero() public {
        vm.prank(owner);
        vm.expectRevert(ProofOfHumanity.InvalidIssuer.selector);
        poh.setIssuer(address(0));
    }

    function test_SetIssuer_UpdatesAndEmits() public {
        vm.expectEmit(true, true, true, true, address(poh));
        emit ProofOfHumanity.IssuerUpdated(issuer, newIssuer);
        vm.prank(owner);
        poh.setIssuer(newIssuer);
        assertEq(poh.issuer(), newIssuer);
    }

    function test_IssuerRotation_NewIssuerWorksOldDoesNot() public {
        vm.prank(owner);
        poh.setIssuer(newIssuer);

        HumanityVoucher memory v = _defaultVoucher(alice, NULL_A);

        // Old issuer's signature is now rejected.
        bytes memory oldSig = _sign(ISSUER_PK, v);
        vm.prank(relayer);
        vm.expectRevert(ProofOfHumanity.InvalidSigner.selector);
        poh.mintWithVoucher(v, oldSig);

        // New issuer's signature works.
        uint256 id = _mint(NEW_ISSUER_PK, v);
        assertEq(id, 1);
        assertEq(poh.ownerOf(1), alice);
    }

    /*//////////////////////////////////////////////////////////////
                            HAPPY PATH
    //////////////////////////////////////////////////////////////*/

    function test_HappyPath_MintStoresEpochAndLocks() public {
        HumanityVoucher memory v = _defaultVoucher(alice, NULL_A);

        vm.expectEmit(true, true, true, true, address(poh));
        emit ProofOfHumanity.HumanityMinted(1, NULL_A, alice);

        uint256 id = _mint(ISSUER_PK, v);

        assertEq(id, 1);
        assertEq(poh.ownerOf(1), alice);
        assertEq(poh.balanceOf(alice), 1);
        assertTrue(poh.locked(1));
        assertEq(poh.nextId(), 2);
        assertEq(poh.tokenOfNullifier(NULL_A), 1);
        assertEq(poh.epochOf(1), poh.currentEpoch());
        assertTrue(poh.isValid(1));
    }

    function test_LockedEventEmittedOnMint() public {
        HumanityVoucher memory v = _defaultVoucher(alice, NULL_A);
        bytes memory sig = _sign(ISSUER_PK, v);
        vm.expectEmit(true, false, false, true, address(poh));
        emit IERC5192.Locked(1);
        vm.prank(relayer);
        poh.mintWithVoucher(v, sig);
    }

    function test_RelayerCannotRedirectToken() public {
        // Token always goes to voucher.to, regardless of msg.sender (relayer).
        HumanityVoucher memory v = _defaultVoucher(alice, NULL_A);
        _mint(ISSUER_PK, v);
        assertEq(poh.ownerOf(1), alice);
        assertEq(poh.balanceOf(relayer), 0);
    }

    /*//////////////////////////////////////////////////////////////
                        EPOCH / VALIDITY
    //////////////////////////////////////////////////////////////*/

    function test_CurrentEpoch_MatchesFormula() public view {
        assertEq(poh.currentEpoch(), uint32(block.timestamp / EPOCH));
    }

    function test_Constants_EpochAndValidity() public view {
        assertEq(poh.EPOCH(), 90 days);
        assertEq(poh.VALIDITY_EPOCHS(), 4);
    }

    function test_IsValid_TrueWithinWindowFalseAfter() public {
        HumanityVoucher memory v = _defaultVoucher(alice, NULL_A);
        _mint(ISSUER_PK, v);
        assertTrue(poh.isValid(1));

        // Still valid at exactly verifiedEpoch + VALIDITY_EPOCHS.
        vm.warp(block.timestamp + 4 * EPOCH);
        assertTrue(poh.isValid(1));

        // One epoch past the window -> invalid.
        vm.warp(block.timestamp + EPOCH);
        assertFalse(poh.isValid(1));
    }

    /*//////////////////////////////////////////////////////////////
                            TOKEN URI
    //////////////////////////////////////////////////////////////*/

    function test_TokenURI_MinimalNoPersonalData() public {
        HumanityVoucher memory v = _defaultVoucher(alice, NULL_A);
        _mint(ISSUER_PK, v);

        string memory uri = poh.tokenURI(1);
        assertTrue(_startsWith(uri, "data:application/json;base64,"));

        string memory json = _decodeDataUri(uri);
        assertTrue(_contains(json, "Proof of Humanity #1"));
        assertTrue(_contains(json, '"trait_type":"Status","value":"Verified Human"'));
        assertTrue(_contains(json, '"trait_type":"Valid","value":"true"'));

        // NO personal data anywhere.
        assertFalse(_contains(json, "Nationality"));
        assertFalse(_contains(json, "Gender"));
        assertFalse(_contains(json, "Age"));
        assertFalse(_contains(json, "OFAC"));
        assertFalse(_contains(json, "ARG"));
    }

    function test_TokenURI_ValidFalseAfterExpiry() public {
        HumanityVoucher memory v = _defaultVoucher(alice, NULL_A);
        _mint(ISSUER_PK, v);
        vm.warp(block.timestamp + 5 * EPOCH); // past the validity window
        string memory json = _decodeDataUri(poh.tokenURI(1));
        assertTrue(_contains(json, '"trait_type":"Valid","value":"false"'));
    }

    function test_TokenURI_RevertsForNonexistent() public {
        vm.expectRevert(abi.encodeWithSignature("ERC721NonexistentToken(uint256)", uint256(999)));
        poh.tokenURI(999);
    }

    /*//////////////////////////////////////////////////////////////
                        VOUCHER VALIDATION (FAIL CLOSED)
    //////////////////////////////////////////////////////////////*/

    function test_Revert_WrongSigner() public {
        HumanityVoucher memory v = _defaultVoucher(alice, NULL_A);
        bytes memory sig = _sign(NEW_ISSUER_PK, v); // not the current issuer
        vm.prank(relayer);
        vm.expectRevert(ProofOfHumanity.InvalidSigner.selector);
        poh.mintWithVoucher(v, sig);
    }

    function test_Revert_TamperedNullifier() public {
        HumanityVoucher memory v = _defaultVoucher(alice, NULL_A);
        bytes memory sig = _sign(ISSUER_PK, v);

        // Tamper a field AFTER signing -> digest changes -> recovered != issuer.
        v.nullifier = NULL_B;
        vm.prank(relayer);
        vm.expectRevert(ProofOfHumanity.InvalidSigner.selector);
        poh.mintWithVoucher(v, sig);
    }

    function test_Revert_TamperedEpoch() public {
        HumanityVoucher memory v = _defaultVoucher(alice, NULL_A);
        bytes memory sig = _sign(ISSUER_PK, v);
        v.epoch = v.epoch + 100; // inflate validity after signing
        vm.prank(relayer);
        vm.expectRevert(ProofOfHumanity.InvalidSigner.selector);
        poh.mintWithVoucher(v, sig);
    }

    function test_Revert_ZeroRecipient() public {
        HumanityVoucher memory v = _defaultVoucher(address(0), NULL_A);
        bytes memory sig = _sign(ISSUER_PK, v);
        vm.prank(relayer);
        vm.expectRevert(ProofOfHumanity.InvalidRecipient.selector);
        poh.mintWithVoucher(v, sig);
    }

    /*//////////////////////////////////////////////////////////////
                            SOULBOUND
    //////////////////////////////////////////////////////////////*/

    function test_Soulbound_TransferFromReverts() public {
        _mint(ISSUER_PK, _defaultVoucher(alice, NULL_A));
        vm.prank(alice);
        vm.expectRevert(ProofOfHumanity.Soulbound.selector);
        poh.transferFrom(alice, bob, 1);
    }

    function test_Soulbound_SafeTransferFromReverts() public {
        _mint(ISSUER_PK, _defaultVoucher(alice, NULL_A));
        vm.startPrank(alice);
        vm.expectRevert(ProofOfHumanity.Soulbound.selector);
        poh.safeTransferFrom(alice, bob, 1);
        vm.expectRevert(ProofOfHumanity.Soulbound.selector);
        poh.safeTransferFrom(alice, bob, 1, "");
        vm.stopPrank();
    }

    function test_Soulbound_ApproveReverts() public {
        _mint(ISSUER_PK, _defaultVoucher(alice, NULL_A));
        vm.prank(alice);
        vm.expectRevert(ProofOfHumanity.Soulbound.selector);
        poh.approve(bob, 1);
    }

    function test_Soulbound_SetApprovalForAllReverts() public {
        _mint(ISSUER_PK, _defaultVoucher(alice, NULL_A));
        vm.prank(alice);
        vm.expectRevert(ProofOfHumanity.Soulbound.selector);
        poh.setApprovalForAll(bob, true);
    }

    function test_SupportsInterface() public view {
        assertTrue(poh.supportsInterface(0xb45a3c0e)); // ERC-5192
        assertTrue(poh.supportsInterface(0x80ac58cd)); // ERC-721
        assertTrue(poh.supportsInterface(0x5b5e139f)); // ERC-721 Metadata
        assertTrue(poh.supportsInterface(0x01ffc9a7)); // ERC-165
        assertFalse(poh.supportsInterface(0xffffffff));
    }

    /*//////////////////////////////////////////////////////////////
                NULLIFIER UNIQUENESS / EPOCH REFRESH
    //////////////////////////////////////////////////////////////*/

    function test_Refresh_SameTokenUpdatesEpochMonotonically() public {
        HumanityVoucher memory v1 = _defaultVoucher(alice, NULL_A);
        uint32 e1 = v1.epoch;
        _mint(ISSUER_PK, v1);

        // A newer epoch refreshes the token in place (no new id).
        HumanityVoucher memory v2 = _defaultVoucher(alice, NULL_A);
        v2.epoch = e1 + 2;

        vm.expectEmit(true, true, true, true, address(poh));
        emit ProofOfHumanity.HumanityRefreshed(1, NULL_A, e1 + 2);
        uint256 id = _mint(ISSUER_PK, v2);

        assertEq(id, 1); // same token
        assertEq(poh.nextId(), 2); // no new id consumed
        assertEq(poh.balanceOf(alice), 1); // still exactly one token
        assertEq(poh.epochOf(1), e1 + 2);
    }

    function test_Revert_ReplayedVoucher() public {
        HumanityVoucher memory v = _defaultVoucher(alice, NULL_A);
        bytes memory sig = _sign(ISSUER_PK, v);

        vm.prank(relayer);
        uint256 id = poh.mintWithVoucher(v, sig);

        vm.prank(relayer);
        vm.expectRevert(ProofOfHumanity.VoucherReplayed.selector);
        poh.mintWithVoucher(v, sig);

        assertEq(id, 1);
        assertEq(poh.balanceOf(alice), 1);
        assertEq(poh.nextId(), 2);
        assertEq(poh.epochOf(1), v.epoch);
    }

    function test_Revert_EpochDowngrade() public {
        HumanityVoucher memory v1 = _defaultVoucher(alice, NULL_A);
        v1.epoch = v1.epoch + 5;
        _mint(ISSUER_PK, v1);

        // Older epoch than stored -> must NOT downgrade.
        HumanityVoucher memory v2 = _defaultVoucher(alice, NULL_A);
        v2.epoch = v1.epoch - 1;
        bytes memory sig = _sign(ISSUER_PK, v2);
        vm.prank(relayer);
        vm.expectRevert(ProofOfHumanity.EpochDowngrade.selector);
        poh.mintWithVoucher(v2, sig);
    }

    function test_Revert_NullifierReuseAcrossWalletsKeepsOriginalToken() public {
        _mint(ISSUER_PK, _defaultVoucher(alice, NULL_A));

        // Same nullifier, different `to` -> anti-hijack revert.
        HumanityVoucher memory vBob = _defaultVoucher(bob, NULL_A);
        bytes memory sig = _sign(ISSUER_PK, vBob);
        vm.prank(relayer);
        vm.expectRevert(ProofOfHumanity.NullifierOwnerMismatch.selector);
        poh.mintWithVoucher(vBob, sig);

        // The failed wallet-rebinding attempt cannot allocate or remap a token.
        assertEq(poh.tokenOfNullifier(NULL_A), 1);
        assertEq(poh.balanceOf(alice), 1);
        assertEq(poh.balanceOf(bob), 0);
        assertEq(poh.nextId(), 2);
        assertEq(poh.ownerOf(1), alice);
    }

    function test_DistinctNullifiersMintDistinctTokens() public {
        _mint(ISSUER_PK, _defaultVoucher(alice, NULL_A));
        _mint(ISSUER_PK, _defaultVoucher(bob, NULL_B));
        assertEq(poh.ownerOf(1), alice);
        assertEq(poh.ownerOf(2), bob);
        assertEq(poh.nextId(), 3);
        assertEq(poh.tokenOfNullifier(NULL_A), 1);
        assertEq(poh.tokenOfNullifier(NULL_B), 2);
    }

    /*//////////////////////////////////////////////////////////////
                            VIEWS
    //////////////////////////////////////////////////////////////*/

    function test_Views_RevertForNonexistent() public {
        vm.expectRevert(abi.encodeWithSignature("ERC721NonexistentToken(uint256)", uint256(1)));
        poh.epochOf(1);
        vm.expectRevert(abi.encodeWithSignature("ERC721NonexistentToken(uint256)", uint256(1)));
        poh.isValid(1);
        vm.expectRevert(abi.encodeWithSignature("ERC721NonexistentToken(uint256)", uint256(1)));
        poh.locked(1);
    }

    /*//////////////////////////////////////////////////////////////
                    EIP-712 DOMAIN / TYPE HASH (SPEC MATCH)
    //////////////////////////////////////////////////////////////*/

    function test_EIP712_TypeHashMatchesSpec() public view {
        bytes32 expected = keccak256("HumanityVoucher(address to,uint256 nullifier,uint32 epoch)");
        assertEq(poh.VOUCHER_TYPEHASH(), expected);
    }

    function test_EIP712_DomainAndDigestMatchIndependentDerivation() public view {
        HumanityVoucher memory v = _defaultVoucher(alice, NULL_A);

        bytes32 domainTypeHash =
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
        bytes32 domainSep = keccak256(
            abi.encode(
                domainTypeHash, keccak256(bytes("ProofOfHumanity")), keccak256(bytes("1")), block.chainid, address(poh)
            )
        );
        assertEq(domainSep, poh.domainSeparator());

        bytes32 structHash = keccak256(abi.encode(poh.VOUCHER_TYPEHASH(), v.to, v.nullifier, v.epoch));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSep, structHash));
        assertEq(digest, poh.hashVoucher(v));
    }

    function test_EIP712_VoucherSignedForAnotherChainReverts() public {
        HumanityVoucher memory v = _defaultVoucher(alice, NULL_A);
        bytes memory chainASignature = _sign(ISSUER_PK, v);

        vm.chainId(block.chainid + 1);
        vm.prank(relayer);
        vm.expectRevert(ProofOfHumanity.InvalidSigner.selector);
        poh.mintWithVoucher(v, chainASignature);
    }

    /*//////////////////////////////////////////////////////////////
                                FUZZ
    //////////////////////////////////////////////////////////////*/

    function testFuzz_NullifierNeverAllocatesASecondToken(
        uint256 nullifier,
        address firstWallet,
        address secondWallet,
        uint16 epochStep
    ) public {
        vm.assume(firstWallet != address(0));
        vm.assume(secondWallet != address(0));
        vm.assume(secondWallet != firstWallet);

        HumanityVoucher memory initial = _defaultVoucher(firstWallet, nullifier);
        uint256 tokenId = _mint(ISSUER_PK, initial);

        HumanityVoucher memory refresh = initial;
        refresh.epoch = initial.epoch + uint32(bound(epochStep, 1, 1_000));
        assertEq(_mint(ISSUER_PK, refresh), tokenId);

        HumanityVoucher memory rebound = refresh;
        rebound.to = secondWallet;
        rebound.epoch++;
        bytes memory reboundSig = _sign(ISSUER_PK, rebound);
        vm.prank(relayer);
        vm.expectRevert(ProofOfHumanity.NullifierOwnerMismatch.selector);
        poh.mintWithVoucher(rebound, reboundSig);

        assertEq(poh.tokenOfNullifier(nullifier), tokenId);
        assertEq(poh.ownerOf(tokenId), firstWallet);
        assertEq(poh.balanceOf(firstWallet), 1);
        assertEq(poh.balanceOf(secondWallet), 0);
        assertEq(poh.nextId(), 2);
    }

    /*//////////////////////////////////////////////////////////////
                        STRING / BASE64 TEST UTILS
    //////////////////////////////////////////////////////////////*/

    function _startsWith(string memory s, string memory prefix) internal pure returns (bool) {
        bytes memory bs = bytes(s);
        bytes memory bp = bytes(prefix);
        if (bp.length > bs.length) return false;
        for (uint256 i = 0; i < bp.length; i++) {
            if (bs[i] != bp[i]) return false;
        }
        return true;
    }

    function _contains(string memory haystack, string memory needle) internal pure returns (bool) {
        bytes memory h = bytes(haystack);
        bytes memory n = bytes(needle);
        if (n.length == 0) return true;
        if (n.length > h.length) return false;
        for (uint256 i = 0; i <= h.length - n.length; i++) {
            bool ok = true;
            for (uint256 j = 0; j < n.length; j++) {
                if (h[i + j] != n[j]) {
                    ok = false;
                    break;
                }
            }
            if (ok) return true;
        }
        return false;
    }

    /// @dev Strip the `data:application/json;base64,` prefix and base64-decode.
    function _decodeDataUri(string memory uri) internal pure returns (string memory) {
        bytes memory b = bytes(uri);
        uint256 start = bytes("data:application/json;base64,").length;
        bytes memory payload = new bytes(b.length - start);
        for (uint256 i = start; i < b.length; i++) {
            payload[i - start] = b[i];
        }
        return string(_base64Decode(payload));
    }

    function _base64Decode(bytes memory data) internal pure returns (bytes memory) {
        uint256 len = data.length;
        if (len == 0) return new bytes(0);
        require(len % 4 == 0, "bad base64 length");

        bytes memory table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        uint8[128] memory inv;
        for (uint8 i = 0; i < 64; i++) {
            inv[uint8(table[i])] = i;
        }

        uint256 pad;
        if (data[len - 1] == "=") pad++;
        if (data[len - 2] == "=") pad++;

        uint256 outLen = (len / 4) * 3 - pad;
        bytes memory out = new bytes(outLen);
        uint256 o;
        for (uint256 i = 0; i < len; i += 4) {
            uint256 chunk = (uint256(inv[uint8(data[i])]) << 18) | (uint256(inv[uint8(data[i + 1])]) << 12)
                | (uint256(inv[uint8(data[i + 2])]) << 6) | uint256(inv[uint8(data[i + 3])]);
            if (o < outLen) out[o++] = bytes1(uint8(chunk >> 16));
            if (o < outLen) out[o++] = bytes1(uint8(chunk >> 8));
            if (o < outLen) out[o++] = bytes1(uint8(chunk));
        }
        return out;
    }
}
