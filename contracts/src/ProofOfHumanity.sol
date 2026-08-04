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

/// @notice Public, anonymous attributes carried by a Proof-of-Humanity token.
/// @dev These are the ONLY things the token ever exposes. It never stores or
///      reveals identity (no name, date of birth, passport number, MRZ, etc).
/// @param ageFlags   Monotone age-threshold bitfield: bit0=13+, bit1=18+,
///                   bit2=21+, bit3=65+. Upper bits are reserved (must be 0).
/// @param nationality ISO-3166-1 alpha-3 country code packed as 3 ASCII bytes
///                   (e.g. "ARG"). `bytes3(0)` means "not disclosed".
/// @param gender     Raw MRZ sex byte: 'M' (0x4D), 'F' (0x46) or '<' (0x3C,
///                   unspecified). `0` means "not disclosed".
/// @param ofacClear  True if the issuer attests the human is not on an OFAC list.
/// @param expiry     Unix timestamp after which the credential is stale.
struct Attributes {
    uint8 ageFlags;
    bytes3 nationality;
    uint8 gender;
    bool ofacClear;
    uint64 expiry;
}

/// @notice Signed off-chain attestation ("humanity voucher") that a backend
///         which already verified a Self (self.xyz) ZK passport proof issues to
///         a human, to be redeemed on-chain via {ProofOfHumanity.mintWithVoucher}.
/// @param to         The address that will hold (or already holds) the token.
/// @param nullifier  Self's deterministic per-identity nullifier (a BN254 field
///                   element). Enforces one-human-one-token PER chain.
/// @param ageFlags   See {Attributes.ageFlags}.
/// @param nationality See {Attributes.nationality}.
/// @param gender     See {Attributes.gender}.
/// @param ofacClear  See {Attributes.ofacClear}.
/// @param expiry     Voucher deadline AND resulting credential expiry. The
///                   voucher is only redeemable while `expiry > block.timestamp`.
struct HumanityVoucher {
    address to;
    uint256 nullifier;
    uint8 ageFlags;
    bytes3 nationality;
    uint8 gender;
    bool ofacClear;
    uint64 expiry;
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
///         the exact same nullifier-uniqueness / accumulation logic that
///         {ProofOfHumanity.mintWithVoucher} uses today.
/// @dev INTENTIONALLY UNIMPLEMENTED in this MVP. Declared only to fix the ABI
///      seam so the trustless path is an additive, non-breaking change.
interface IHumanityProofVerifier {
    function verifyAndExtract(bytes calldata proof, uint256[] calldata publicSignals, bytes calldata userContextData)
        external
        view
        returns (uint256 nullifier, Attributes memory attrs, address subject);
}

/// @title On-chain PoH card renderer seam.
/// @notice Pluggable renderer that turns a token's public traits into an SVG image
///         data-URI for {ProofOfHumanity.tokenURI}. Implemented by {PoHCardRenderer};
///         kept as a separate contract so the ~8 KB card art never bloats the token.
interface IPoHCardRenderer {
    function render(uint256 tokenId, uint8 ageFlags, bytes3 nationality, uint8 gender)
        external
        pure
        returns (string memory);
}

/*//////////////////////////////////////////////////////////////
                        PROOF OF HUMANITY
//////////////////////////////////////////////////////////////*/

/// @title Proof of Humanity
/// @notice A soulbound (ERC-5192), anonymous, cross-chain "unique human"
///         credential minted for anyone verified via a Self ZK passport proof.
///         The token carries only PUBLIC anonymous traits (nationality, age
///         flags, gender, OFAC-clear) and NEVER identity.
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
    /// @dev Type string:
    ///      "HumanityVoucher(address to,uint256 nullifier,uint8 ageFlags,bytes3 nationality,uint8 gender,bool ofacClear,uint64 expiry)"
    bytes32 public constant VOUCHER_TYPEHASH = keccak256(
        "HumanityVoucher(address to,uint256 nullifier,uint8 ageFlags,bytes3 nationality,uint8 gender,bool ofacClear,uint64 expiry)"
    );

    /// @dev Age-threshold bit masks.
    uint8 private constant AGE_13 = 0x01;
    uint8 private constant AGE_18 = 0x02;
    uint8 private constant AGE_21 = 0x04;
    uint8 private constant AGE_65 = 0x08;

    string private constant DESCRIPTION =
        "Soulbound, anonymous proof of unique humanity verified via a zero-knowledge passport proof. Carries only public anonymous traits; never identity.";

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

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

    /// @dev Per-token public attributes.
    mapping(uint256 tokenId => Attributes) private _attributes;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Emitted when a brand-new humanity token is minted.
    event HumanityMinted(uint256 indexed tokenId, uint256 indexed nullifier, address indexed to);

    /// @notice Emitted when an existing token is upgraded by a repeat proof for
    ///         the same nullifier (new age bits OR-ed in, expiry refreshed, etc).
    event HumanityUpgraded(uint256 indexed tokenId, uint256 indexed nullifier, uint8 ageFlags);

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
    /// @dev `voucher.expiry <= block.timestamp`; the voucher is expired.
    error VoucherExpired();
    /// @dev A token already exists for this nullifier but is held by a different
    ///      address than `voucher.to` (attempted hijack of another human's token).
    error NullifierOwnerMismatch();
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
                              MINT / UPGRADE
    //////////////////////////////////////////////////////////////*/

    /// @notice Redeem a signed {HumanityVoucher} to mint (or upgrade) the caller's
    ///         Proof-of-Humanity token. `msg.sender` may be a relayer: the token
    ///         is always credited to `voucher.to`, and the issuer signature over
    ///         `to` is authoritative, so no `msg.sender` binding is needed.
    /// @param voucher   The attributes + recipient + nullifier attested by the issuer.
    /// @param signature The issuer's EIP-712 signature over `voucher`.
    /// @return tokenId  The minted or upgraded token id.
    function mintWithVoucher(HumanityVoucher calldata voucher, bytes calldata signature)
        external
        returns (uint256 tokenId)
    {
        // --- Fail-closed validation ---
        if (voucher.to == address(0)) revert InvalidRecipient();
        if (voucher.expiry <= block.timestamp) revert VoucherExpired();

        address signer = ECDSA.recover(_hashTypedDataV4(_structHash(voucher)), signature);
        if (signer != issuer) revert InvalidSigner();

        uint256 existingId = tokenOfNullifier[voucher.nullifier];

        if (existingId == 0) {
            // --- New human: mint a fresh soulbound token ---
            tokenId = nextId++;
            tokenOfNullifier[voucher.nullifier] = tokenId;
            _attributes[tokenId] = Attributes({
                ageFlags: voucher.ageFlags,
                nationality: voucher.nationality,
                gender: voucher.gender,
                ofacClear: voucher.ofacClear,
                expiry: voucher.expiry
            });
            // Non-safe mint: no ERC721Receiver callback (no reentrancy surface,
            // and soulbound credentials must reach contract wallets too).
            _mint(voucher.to, tokenId);
            emit Locked(tokenId); // ERC-5192
            emit HumanityMinted(tokenId, voucher.nullifier, voucher.to);
        } else {
            // --- Repeat proof for the SAME nullifier: upgrade in place ---
            // Anti-hijack: the voucher must name the current holder.
            if (ownerOf(existingId) != voucher.to) revert NullifierOwnerMismatch();

            Attributes storage a = _attributes[existingId];
            a.ageFlags |= voucher.ageFlags; // monotone: only add age thresholds
            if (voucher.expiry > a.expiry) a.expiry = voucher.expiry; // refresh if newer
            a.nationality = voucher.nationality;
            a.gender = voucher.gender;
            a.ofacClear = voucher.ofacClear;

            tokenId = existingId;
            emit HumanityUpgraded(existingId, voucher.nullifier, a.ageFlags);
        }
    }

    /// @dev EIP-712 struct hash of a voucher.
    function _structHash(HumanityVoucher calldata v) private pure returns (bytes32) {
        return keccak256(
            abi.encode(VOUCHER_TYPEHASH, v.to, v.nullifier, v.ageFlags, v.nationality, v.gender, v.ofacClear, v.expiry)
        );
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

    /// @notice The public attributes of `tokenId`. Reverts if it does not exist.
    function attributesOf(uint256 tokenId) external view returns (Attributes memory) {
        _requireOwned(tokenId);
        return _attributes[tokenId];
    }

    /// @notice Whether `tokenId`'s credential has passed its expiry. Reverts if
    ///         the token does not exist.
    function isExpired(uint256 tokenId) external view returns (bool) {
        _requireOwned(tokenId);
        return _attributes[tokenId].expiry <= block.timestamp;
    }

    /// @inheritdoc IERC5192
    /// @dev Every existing token is permanently locked; querying a nonexistent
    ///      token reverts (per ERC-5192).
    function locked(uint256 tokenId) external view returns (bool) {
        _requireOwned(tokenId);
        return true;
    }

    /// @notice Fully on-chain, base64-encoded JSON metadata. Reverts for a
    ///         nonexistent token. Renders each public trait only when present.
    function tokenURI(uint256 tokenId) public view override returns (string memory) {
        _requireOwned(tokenId);
        Attributes memory a = _attributes[tokenId];

        string[] memory parts = new string[](8);
        uint256 n = 0;

        if (a.nationality != bytes3(0)) {
            parts[n++] = string.concat('{"trait_type":"Nationality","value":"', _natString(a.nationality), '"}');
        }
        if (a.gender != 0) {
            parts[n++] = string.concat('{"trait_type":"Gender","value":"', _genderString(a.gender), '"}');
        }
        if ((a.ageFlags & AGE_13) != 0) parts[n++] = _ageObj("13+");
        if ((a.ageFlags & AGE_18) != 0) parts[n++] = _ageObj("18+");
        if ((a.ageFlags & AGE_21) != 0) parts[n++] = _ageObj("21+");
        if ((a.ageFlags & AGE_65) != 0) parts[n++] = _ageObj("65+");
        if (a.ofacClear) parts[n++] = '{"trait_type":"OFAC","value":"clear"}';
        if (a.expiry != 0) {
            parts[n++] =
                string.concat('{"display_type":"date","trait_type":"Expiry","value":', Strings.toString(a.expiry), "}");
        }

        // Optional fully on-chain card art. Omitted (valid JSON) when no renderer
        // is configured. The renderer returns a self-contained data-URI whose only
        // characters are the data-URI prefix + base64, so it needs no JSON-escaping.
        string memory image = cardRenderer == address(0)
            ? ""
            : string.concat(
                ',"image":"',
                IPoHCardRenderer(cardRenderer).render(tokenId, a.ageFlags, a.nationality, a.gender),
                '"'
            );

        string memory json = string.concat(
            '{"name":"Proof of Humanity #',
            Strings.toString(tokenId),
            '","description":"',
            DESCRIPTION,
            '"',
            image,
            ',"attributes":[',
            _join(parts, n),
            "]}"
        );

        return string.concat("data:application/json;base64,", Base64.encode(bytes(json)));
    }

    /*//////////////////////////////////////////////////////////////
                          METADATA HELPERS
    //////////////////////////////////////////////////////////////*/

    function _ageObj(string memory value) private pure returns (string memory) {
        return string.concat('{"trait_type":"Age","value":"', value, '"}');
    }

    /// @dev Decode a packed ISO-3166 alpha-3 code back to its 3 ASCII characters.
    function _natString(bytes3 nat) private pure returns (string memory) {
        bytes memory b = new bytes(3);
        b[0] = nat[0];
        b[1] = nat[1];
        b[2] = nat[2];
        return string(b);
    }

    /// @dev Map the raw MRZ sex byte to a human-readable value.
    function _genderString(uint8 g) private pure returns (string memory) {
        if (g == 0x4D) return "male"; // 'M'
        if (g == 0x46) return "female"; // 'F'
        return "other"; // '<' (unspecified) or anything else
    }

    /// @dev Comma-join the first `count` entries of `parts`.
    function _join(string[] memory parts, uint256 count) private pure returns (string memory out) {
        for (uint256 i = 0; i < count; i++) {
            out = i == 0 ? parts[i] : string.concat(out, ",", parts[i]);
        }
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
