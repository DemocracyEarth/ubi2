// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {Base64} from "@openzeppelin/contracts/utils/Base64.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";

/*//////////////////////////////////////////////////////////////
                        SHARED TYPES
//////////////////////////////////////////////////////////////*/

/// @notice Signed off-chain attestation ("humanity voucher") that a backend
///         which already verified a Self (self.xyz) ZK passport proof issues to
///         a human, to be redeemed on-chain via {ProofOfHumanity.mintWithVoucher}.
/// @dev MINIMAL by design: it carries NO personal attributes (no nationality,
///      gender, age or expiry date). It only asserts "this address belongs to a
///      unique verified human, first seen in `epoch`". Predicates over identity
///      (age / nationality / sanctions) are proven off-chain on demand via
///      zero-knowledge, never stored on-chain.
/// @param to        The address that will hold (or already holds) the token.
/// @param nullifier Self's deterministic per-identity nullifier (a BN254 field
///                  element). Enforces one-human-one-token PER chain.
/// @param epoch     The coarse validity epoch in which the human was verified
///                  (`block.timestamp / EPOCH`). Stored on-chain to derive a
///                  coarse credential validity window; carries no exact date.
struct HumanityVoucher {
    address to;
    uint256 nullifier;
    uint32 epoch;
}

/*//////////////////////////////////////////////////////////////
                        INTERFACES
//////////////////////////////////////////////////////////////*/

/// @title ERC-5192: Minimal Soulbound NFTs
/// @dev Interface id is `0xb45a3c0e` (the selector of `locked(uint256)`).
interface IERC5192 {
    /// @notice Emitted when the locking status is set to locked.
    /// @dev The token issuer MUST emit this on mint of a permanently-locked token.
    event Locked(uint256 tokenId);

    /// @notice Emitted when the locking status is set to unlocked.
    /// @dev Never emitted by this contract; tokens are permanently soulbound.
    event Unlocked(uint256 tokenId);

    /// @notice Returns the locking status of a Soulbound Token.
    /// @dev SBTs assigned to the zero address are invalid; querying them throws.
    function locked(uint256 tokenId) external view returns (bool);
}

/// @title Design seam for the FUTURE fully-trustless minting path.
/// @notice In the trustless upgrade, instead of trusting an issuer signature the
///         contract verifies the Groth16 passport proof on-chain against a
///         mirrored Self identity-registry Merkle root (kept fresh by an oracle
///         that bridges Self's root cross-chain). A `mintWithProof(bytes proof,
///         uint256[] publicSignals, bytes userContextData)` entrypoint would call
///         {verifyAndExtract} on an implementation of this interface, then apply
///         the exact same nullifier-uniqueness logic that
///         {ProofOfHumanity.mintWithVoucher} uses today.
/// @dev INTENTIONALLY UNIMPLEMENTED in this MVP. Declared only to fix the ABI
///      seam so the trustless path is an additive, non-breaking change. It
///      extracts only the nullifier + subject — no personal attributes ever
///      cross the on-chain boundary.
interface IHumanityProofVerifier {
    function verifyAndExtract(bytes calldata proof, uint256[] calldata publicSignals, bytes calldata userContextData)
        external
        view
        returns (uint256 nullifier, address subject);
}

/// @title On-chain PoH card renderer seam.
/// @notice Pluggable renderer that turns a token's anonymous id into an SVG image
///         data-URI for {ProofOfHumanity.tokenURI}. Implemented by {PoHCardRenderer};
///         kept as a separate contract so the card art never bloats the token.
interface IPoHCardRenderer {
    function render(uint256 tokenId, uint256 nullifier) external pure returns (string memory);
}

/*//////////////////////////////////////////////////////////////
                        PROOF OF HUMANITY
//////////////////////////////////////////////////////////////*/

/// @title Proof of Humanity
/// @notice A soulbound (ERC-5192), anonymous, cross-chain "unique human"
///         credential minted for anyone verified via a Self ZK passport proof.
///         The token carries NO personal data whatsoever — only a unique-human
///         nullifier and a coarse validity epoch. It never stores or reveals
///         nationality, gender, age or identity. Predicates over those live
///         off-chain as zero-knowledge proofs, revealed only on demand.
/// @dev MVP trust model: proofofhumanity.org's backend verifies the Self proof
///      off-chain and signs an EIP-712 {HumanityVoucher}; the human (or a
///      relayer on their behalf) redeems it here. Uniqueness is enforced per
///      chain by Self's deterministic nullifier. Deploy the identical bytecode
///      on any EVM chain for cross-chain coverage.
contract ProofOfHumanity is ERC721, Ownable, EIP712, IERC5192 {
    using ECDSA for bytes32;

    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @dev ERC-5192 interface id: `bytes4(keccak256("locked(uint256)"))`.
    bytes4 public constant ERC5192_INTERFACE_ID = 0xb45a3c0e;

    /// @notice EIP-712 type hash of {HumanityVoucher}.
    /// @dev Type string: "HumanityVoucher(address to,uint256 nullifier,uint32 epoch)".
    bytes32 public constant VOUCHER_TYPEHASH = keccak256("HumanityVoucher(address to,uint256 nullifier,uint32 epoch)");

    /// @notice Length of a validity epoch. `currentEpoch() = block.timestamp / EPOCH`.
    uint256 public constant EPOCH = 90 days;

    /// @notice How many epochs a credential stays valid after its verified epoch.
    ///         `VALIDITY_EPOCHS = 4` epochs of 90 days is ~1 year.
    uint32 public constant VALIDITY_EPOCHS = 4;

    string private constant DESCRIPTION =
        "Soulbound, anonymous proof of unique humanity verified via a zero-knowledge passport proof. No personal data on-chain; predicates are proven off-chain on demand.";

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Minimal per-token state: the anonymous nullifier + the epoch the
    ///         human was (re)verified in. NO personal attributes are ever stored.
    struct TokenData {
        uint256 nullifier;
        uint32 epoch;
    }

    /// @notice Address whose EIP-712 signature authorizes vouchers. Rotatable to
    ///         a threshold multisig via {setIssuer}.
    address public issuer;

    /// @notice Optional on-chain card renderer ({IPoHCardRenderer}). When unset
    ///         (`address(0)`), {tokenURI} omits the `"image"` field. Set via
    ///         {setCardRenderer}.
    address public cardRenderer;

    /// @notice Next token id to mint. Token ids start at 1; 0 means "unused".
    uint256 public nextId = 1;

    /// @notice Maps a Self nullifier to the token id it minted (0 = none yet).
    ///         Guarantees one-human-one-token per chain.
    mapping(uint256 nullifier => uint256 tokenId) public tokenOfNullifier;

    /// @dev Per-token minimal state (nullifier + verified epoch).
    mapping(uint256 tokenId => TokenData) private _tokens;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Emitted when a brand-new humanity token is minted.
    event HumanityMinted(uint256 indexed tokenId, uint256 indexed nullifier, address indexed to);

    /// @notice Emitted when an existing token's validity epoch is refreshed by a
    ///         newer proof for the same nullifier (monotonic; never downgrades).
    event HumanityRefreshed(uint256 indexed tokenId, uint256 indexed nullifier, uint32 epoch);

    /// @notice Emitted when the authorized voucher issuer is set or rotated.
    event IssuerUpdated(address indexed previousIssuer, address indexed newIssuer);

    /// @notice Emitted when the on-chain card renderer is set, changed or cleared.
    event CardRendererUpdated(address indexed previousRenderer, address indexed newRenderer);

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @dev The token is soulbound: transfers, approvals and operators are disabled.
    error Soulbound();
    /// @dev The recovered voucher signer is not the current {issuer}.
    error InvalidSigner();
    /// @dev The voucher names the zero address as recipient.
    error InvalidRecipient();
    /// @dev A token already exists for this nullifier but is held by a different
    ///      address than `voucher.to` (attempted hijack of another human's token).
    error NullifierOwnerMismatch();
    /// @dev A refresh voucher carries an older epoch than the one already stored
    ///      (blocks downgrade / stale-epoch replay).
    error EpochDowngrade();
    /// @dev A voucher for the currently stored epoch was already redeemed. Only
    ///      a strictly newer verification epoch may refresh an existing token.
    error VoucherReplayed();
    /// @dev The issuer may not be the zero address.
    error InvalidIssuer();

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @param initialOwner  Admin who can rotate the issuer (Ownable owner).
    /// @param initialIssuer Address whose signatures authorize vouchers.
    constructor(address initialOwner, address initialIssuer)
        ERC721("Proof of Humanity", "POH")
        Ownable(initialOwner)
        EIP712("ProofOfHumanity", "1")
    {
        if (initialIssuer == address(0)) revert InvalidIssuer();
        issuer = initialIssuer;
        emit IssuerUpdated(address(0), initialIssuer);
    }

    /*//////////////////////////////////////////////////////////////
                                ADMIN
    //////////////////////////////////////////////////////////////*/

    /// @notice Rotate the authorized voucher issuer (e.g. to a threshold multisig).
    /// @dev Only the owner. Vouchers signed by the previous issuer stop working.
    function setIssuer(address newIssuer) external onlyOwner {
        if (newIssuer == address(0)) revert InvalidIssuer();
        address previous = issuer;
        issuer = newIssuer;
        emit IssuerUpdated(previous, newIssuer);
    }

    /// @notice Set (or clear) the on-chain card renderer used by {tokenURI}.
    /// @dev Only the owner (same auth as {setIssuer}). Pass `address(0)` to unset,
    ///      which makes {tokenURI} omit the `"image"` field again.
    function setCardRenderer(address newRenderer) external onlyOwner {
        address previous = cardRenderer;
        cardRenderer = newRenderer;
        emit CardRendererUpdated(previous, newRenderer);
    }

    /*//////////////////////////////////////////////////////////////
                              MINT / REFRESH
    //////////////////////////////////////////////////////////////*/

    /// @notice Redeem a signed {HumanityVoucher} to mint (or refresh) the caller's
    ///         Proof-of-Humanity token. `msg.sender` may be a relayer: the token
    ///         is always credited to `voucher.to`, and the issuer signature over
    ///         `to` is authoritative, so no `msg.sender` binding is needed.
    /// @param voucher   The recipient + nullifier + verified epoch attested by the issuer.
    /// @param signature The issuer's EIP-712 signature over `voucher`.
    /// @return tokenId  The minted or refreshed token id.
    function mintWithVoucher(HumanityVoucher calldata voucher, bytes calldata signature)
        external
        returns (uint256 tokenId)
    {
        // --- Fail-closed validation ---
        if (voucher.to == address(0)) revert InvalidRecipient();

        address signer = ECDSA.recover(_hashTypedDataV4(_structHash(voucher)), signature);
        if (signer != issuer) revert InvalidSigner();

        uint256 existingId = tokenOfNullifier[voucher.nullifier];

        if (existingId == 0) {
            // --- New human: mint a fresh soulbound token ---
            tokenId = nextId++;
            tokenOfNullifier[voucher.nullifier] = tokenId;
            _tokens[tokenId] = TokenData({nullifier: voucher.nullifier, epoch: voucher.epoch});
            // Non-safe mint: no ERC721Receiver callback (no reentrancy surface,
            // and soulbound credentials must reach contract wallets too).
            _mint(voucher.to, tokenId);
            emit Locked(tokenId); // ERC-5192
            emit HumanityMinted(tokenId, voucher.nullifier, voucher.to);
        } else {
            // --- Repeat proof for the SAME nullifier: refresh the epoch in place ---
            // Anti-hijack: the voucher must name the current holder.
            if (ownerOf(existingId) != voucher.to) revert NullifierOwnerMismatch();

            TokenData storage t = _tokens[existingId];
            // Strictly monotonic: reject identical replays and stale downgrades.
            if (voucher.epoch < t.epoch) revert EpochDowngrade();
            if (voucher.epoch == t.epoch) revert VoucherReplayed();
            t.epoch = voucher.epoch;

            tokenId = existingId;
            emit HumanityRefreshed(existingId, voucher.nullifier, voucher.epoch);
        }
    }

    /// @dev EIP-712 struct hash of a voucher.
    function _structHash(HumanityVoucher calldata v) private pure returns (bytes32) {
        return keccak256(abi.encode(VOUCHER_TYPEHASH, v.to, v.nullifier, v.epoch));
    }

    /// @notice The EIP-712 digest a signer must sign for `voucher` (helper for
    ///         relayers / off-chain tooling / tests).
    function hashVoucher(HumanityVoucher calldata voucher) external view returns (bytes32) {
        return _hashTypedDataV4(_structHash(voucher));
    }

    /// @notice The EIP-712 domain separator for this contract/chain.
    function domainSeparator() external view returns (bytes32) {
        return _domainSeparatorV4();
    }

    /*//////////////////////////////////////////////////////////////
                                VIEWS
    //////////////////////////////////////////////////////////////*/

    /// @notice The current coarse validity epoch, `block.timestamp / EPOCH`.
    function currentEpoch() public view returns (uint32) {
        return uint32(block.timestamp / EPOCH);
    }

    /// @notice The epoch `tokenId` was last (re)verified in. Reverts if it does
    ///         not exist.
    function epochOf(uint256 tokenId) external view returns (uint32) {
        _requireOwned(tokenId);
        return _tokens[tokenId].epoch;
    }

    /// @notice Whether `tokenId`'s credential is still within its validity window
    ///         (`currentEpoch() <= verifiedEpoch + VALIDITY_EPOCHS`). Reverts if
    ///         the token does not exist.
    function isValid(uint256 tokenId) external view returns (bool) {
        _requireOwned(tokenId);
        return _isValid(_tokens[tokenId].epoch);
    }

    /// @dev Pure validity check against the current epoch.
    function _isValid(uint32 epoch) private view returns (bool) {
        return uint256(currentEpoch()) <= uint256(epoch) + VALIDITY_EPOCHS;
    }

    /// @inheritdoc IERC5192
    /// @dev Every existing token is permanently locked; querying a nonexistent
    ///      token reverts (per ERC-5192).
    function locked(uint256 tokenId) external view returns (bool) {
        _requireOwned(tokenId);
        return true;
    }

    /// @notice Fully on-chain, base64-encoded JSON metadata. Reverts for a
    ///         nonexistent token. Carries only the anonymous status + validity —
    ///         never any personal attribute.
    function tokenURI(uint256 tokenId) public view override returns (string memory) {
        _requireOwned(tokenId);
        TokenData memory t = _tokens[tokenId];

        // Optional fully on-chain card art. Omitted (valid JSON) when no renderer
        // is configured. The renderer returns a self-contained data-URI whose only
        // characters are the data-URI prefix + base64, so it needs no JSON-escaping.
        string memory image = cardRenderer == address(0)
            ? ""
            : string.concat(',"image":"', IPoHCardRenderer(cardRenderer).render(tokenId, t.nullifier), '"');

        string memory json = string.concat(
            '{"name":"Proof of Humanity #',
            Strings.toString(tokenId),
            '","description":"',
            DESCRIPTION,
            '"',
            image,
            ',"attributes":[{"trait_type":"Status","value":"Verified Human"},{"trait_type":"Valid","value":"',
            _isValid(t.epoch) ? "true" : "false",
            '"}]}'
        );

        return string.concat("data:application/json;base64,", Base64.encode(bytes(json)));
    }

    /*//////////////////////////////////////////////////////////////
                        SOULBOUND ENFORCEMENT
    //////////////////////////////////////////////////////////////*/

    /// @dev Block every transfer between two non-zero addresses; allow mint
    ///      (`from == 0`) and burn (`to == 0`). This is the single ERC-5192 lock.
    function _update(address to, uint256 tokenId, address auth) internal override returns (address) {
        address from = _ownerOf(tokenId);
        if (from != address(0) && to != address(0)) revert Soulbound();
        return super._update(to, tokenId, auth);
    }

    /// @dev Approvals are meaningless for a non-transferable token.
    function approve(address, uint256) public pure override {
        revert Soulbound();
    }

    /// @dev Operators are meaningless for a non-transferable token.
    function setApprovalForAll(address, bool) public pure override {
        revert Soulbound();
    }

    /*//////////////////////////////////////////////////////////////
                            INTROSPECTION
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc ERC721
    function supportsInterface(bytes4 interfaceId) public view override(ERC721) returns (bool) {
        return interfaceId == ERC5192_INTERFACE_ID || super.supportsInterface(interfaceId);
    }
}
