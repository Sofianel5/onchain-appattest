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

    // verify signature using DaimoVerifier
    // Address 0xc2b78104907F722DABAc4C69f826a522B2754De4
    function _validateSignature(
        UserOperation calldata userOp,
        bytes32 messageHash
    ) internal override returns (uint256 validationData) {
        bytes signature = userOp.signature;
        if (signature.length < 1) return 0;

        // First bit identifies the keySlot
        uint8 keySlot = uint8(signature[0]);

        // If the keySlot is empty, this is an invalid key
        uint256 x = uint256(keys[keySlot][0]);
        uint256 y = uint256(keys[keySlot][1]);

        // TODO: might need to break apart signature into r and s
        bool valid = P256.verifySignature(messageHash, signature, x, y);

        if (!valid) {
            return SIG_VALIDATION_FAILED;
        }
        return 0;
    }
}
