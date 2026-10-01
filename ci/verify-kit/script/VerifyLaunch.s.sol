// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {RealQueryVerify as V} from "../contracts/shield/verifier/RealQueryVerify.sol";

interface IPool {
    function verifier() external view returns (address);
}

interface IAdapter {
    function ONE_CALL() external view returns (bytes32);
    function verifierForSize(uint256 n) external view returns (address);
    function verifyBatch(bytes calldata proof, uint256[] calldata publicInputs) external view returns (bool);
}

interface ISplit {
    function shape() external view returns (V.Shape memory);
}

/// @notice Checks one launch proof against the live verifier of the launch pool, and sends nothing.
/// @dev env: PROOF, a package proof with its 40-byte NOXP header; PUBLICS, a JSON file whose
///      `.publics` is the 36 limbs. The proof is re-encoded into the verifier's one-call layout
///      exactly as the relayer encodes it for `settleBatch`, then handed to `verifyBatch`.
///      Copied from NOX-SmartContract `script/shield/SettleLaunch.s.sol`, verifyOnly.
contract VerifyLaunch is Script {
    IPool internal constant POOL = IPool(0x8e377752C8890E23A1E9F40eBbD41183Fc6949e2);
    uint256 internal constant HEADER = 40;
    uint256 internal constant WORDS = 12;

    function run() external view {
        IAdapter a = IAdapter(POOL.verifier());
        ISplit v = ISplit(a.verifierForSize(1));
        bytes memory proof = _whole(a, v, _body(vm.envString("PROOF")));
        uint256[] memory words = _words(vm.parseJsonUintArray(vm.readFile(vm.envString("PUBLICS")), ".publics"));
        require(a.verifyBatch(proof, words), "the adapter refuses this proof for these publics");
        console2.log("the live verifier accepts this proof");
    }

    function _body(string memory path) internal view returns (bytes memory) {
        bytes memory f = vm.readFileBinary(path);
        require(f.length > HEADER && f[0] == "N" && f[1] == "O" && f[2] == "X" && f[3] == "P", "not a package proof");
        return _sub(f, HEADER, f.length);
    }

    // head up to the FRI sections plus the nonce region and base count, the claims, then the FRI
    // sections and each base section with its row and path
    function _whole(IAdapter a, ISplit v, bytes memory p) internal view returns (bytes memory) {
        V.Shape memory sh = v.shape();
        (bytes memory head, bytes memory claims) = _headAndClaims(p, sh);
        return abi.encode(a.ONE_CALL(), head, claims, _queries(p, sh), uint256(0), uint256(0));
    }

    function _headAndClaims(bytes memory p, V.Shape memory sh)
        internal
        pure
        returns (bytes memory head, bytes memory claims)
    {
        (uint256[] memory b,,, uint256[] memory fri, uint256 so,) = V.sectionsOf(p, sh);
        (V.Head memory h,) = V.decode(p, sh);
        uint256 region = V.nonceBytes(sh, h.friRoots.length) + 4;
        head = bytes.concat(_sub(p, 0, fri[0]), _sub(p, b[0] - region, b[0]));
        claims = _sub(p, so, so + 4 + sh.nPeriodic * 16);
    }

    function _queries(bytes memory p, V.Shape memory sh) internal pure returns (bytes memory q) {
        (uint256[] memory b, uint256[] memory rows, uint256[] memory perms, uint256[] memory fri,,) =
            V.sectionsOf(p, sh);
        q = _sub(p, fri[0], fri[sh.nq]);
        for (uint256 i = 0; i < sh.nq; ++i) {
            q = bytes.concat(q, _sub(p, b[i], b[i + 1]), _sub(p, rows[i], rows[i + 1]), _sub(p, perms[i], perms[i + 1]));
        }
    }

    // digests are four 64-bit limbs low first, words 6 to 9 one limb each, addresses 48 + 48 + 48 + 16
    function _words(uint256[] memory L) internal pure returns (uint256[] memory w) {
        require(L.length == 36, "a launch statement is 36 limbs");
        w = new uint256[](WORDS);
        uint256[12] memory at = [uint256(0), 4, 8, 12, 16, 20, 24, 25, 26, 27, 28, 32];
        for (uint256 i = 0; i < WORDS; ++i) {
            if (i >= 6 && i <= 9) w[i] = L[at[i]];
            else if (i >= 10) for (uint256 l = 0; l < 4; ++l) w[i] |= L[at[i] + l] << (48 * l);
            else for (uint256 l = 0; l < 4; ++l) w[i] |= L[at[i] + l] << (64 * l);
        }
    }

    function _sub(bytes memory b, uint256 from, uint256 to) internal pure returns (bytes memory o) {
        o = new bytes(to - from);
        for (uint256 i = 0; i < o.length; ++i) o[i] = b[from + i];
    }
}
