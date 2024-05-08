// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

/* solhint-disable avoid-low-level-calls */
/* solhint-disable no-inline-assembly */
/* solhint-disable reason-string */

import "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import "openzeppelin-contracts/contracts/proxy/utils/Initializable.sol";
import "openzeppelin-contracts/contracts/proxy/utils/UUPSUpgradeable.sol";

import "./SimpleAccount.sol";
import "./core/BaseAccount.sol";
import "./callback/TokenCallbackHandler.sol";

import "p256-verifier/P256.sol";

/**
 * Account that validates P-256 signature for UserOperations.
 */
contract P256Account is Initializable, SimpleAccount {
    using ECDSA for bytes32;

    address public verifier;
    IEntryPoint public _entryPoint;
    bytes public publicKey;
    uint256 InactiveTimeLimit;
    address inheritor;
    uint256 lastActiveTime;

    constructor(IEntryPoint _newEntryPoint) SimpleAccount(_newEntryPoint) {}

    function initialize(
        IEntryPoint _newEntryPoint,
        bytes memory _publicKey
    ) public initializer {
        _entryPoint = _newEntryPoint;
        publicKey = _publicKey;
        InactiveTimeLimit = 0;
        inheritor = address(0);
        lastActiveTime = block.timestamp;
    }

    function entryPoint() public view override returns (IEntryPoint) {
        return _entryPoint;
    }

    function setPublicKey(bytes calldata _publicKey) external {
        _requireFromEntryPoint();
        publicKey = _publicKey;
    }

    function setInactiveTimeLimit(uint256 _InactiveTimeLimit) external {
        _requireFromEntryPoint();
        InactiveTimeLimit = _InactiveTimeLimit;
    }

    function setInheritor(address _inheritor) external {
        _requireFromEntryPoint();
        inheritor = _inheritor;
    }

    function inherit() external {
        require(inheritor == msg.sender, "not inheritor");
        require(
            block.timestamp - lastActiveTime > InactiveTimeLimit,
            "not inactive"
        );
        payable(inheritor).transfer(address(this).balance);
    }

    function splitSignatureWithSlicing(
        bytes calldata sig
    ) public pure returns (uint8 v, bytes32 r, bytes32 s) {
        r = bytes32(sig[0:32]); // Copy first 32 bytes

        s = bytes32(sig[32:64]); // Copy 32 more bytes

        v = uint8(bytes1(sig[64:65])); // Copy last byte
    }

    // Get r and s from signature values
    function _extractSignatureValues(
        bytes memory signature
    ) public pure returns (uint256 r, uint256 s) {
        assembly {
            // Load r and s values from signature
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
        }

        return (uint256(r), uint256(s));
    }

    // verify signature using DaimoVerifier
    // Address 0xc2b78104907F722DABAc4C69f826a522B2754De4
    function _validateSignature(
        UserOperation calldata userOp,
        bytes32 messageHash,
        uint256 x,
        uint256 y
    ) internal view returns (uint256 validationData) {
        if (userOp.signature.length < 1) return 0;

        (uint256 r, uint256 s) = _extractSignatureValues(userOp.signature);

        // FML: need to get x and y from the public key
        bool valid = P256.verifySignature(messageHash, r, s, x, y);

        if (!valid) {
            return SIG_VALIDATION_FAILED;
        }
        return 0;
    }
}
