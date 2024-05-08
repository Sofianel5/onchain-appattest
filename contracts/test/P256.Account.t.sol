// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/Counter.sol";
import "../src/core/EntryPoint.sol";
import "../src/P256Account.sol";
import "../src/P256AccountFactory.sol";
import {UserOperation} from "../src/interfaces/UserOperation.sol";

/**
 * @title P256AccountTest
 * @author richard@fun.xyz
 * @notice This is a sanity test for the account function.
 * We want to be able to send a userOp through the entrypoint and have it execute
 */
contract P256AccountTest is Test {
    Counter public counter;
    EntryPoint public entryPoint;
    P256AccountFactory public accountFactory;
    P256Account public account;

    // -------------------- 🧑‍🍼 Account Creation Constants 🧑‍🍼 --------------------
    bytes constant publicKey = "iliketturtles";
    bytes32 constant salt = keccak256("iwanttoberichardwhenigrowup");
    address richard = makeAddr("richard"); // Funder

    /**
     * Helper function to create UserOp
     */
    function _createUserOp(
        bytes memory callData,
        bytes memory signature
    ) internal view returns (UserOperation memory userOp) {
        userOp = UserOperation({
            sender: address(account),
            nonce: entryPoint.getNonce(address(account), 0),
            initCode: "",
            callData: callData,
            callGasLimit: 10_000_000,
            verificationGasLimit: 10_000_000,
            preVerificationGas: 1_000_000,
            maxFeePerGas: 10_000_000,
            maxPriorityFeePerGas: 10_000_000,
            paymasterAndData: "",
            signature: signature
            // signature is the calldata to the P256 Daimo verifier
        });
    }

    /**
     * Deploy the Entrypoint, AccountFactory, and a single account
     * Deposit eth into the entrypoint on behalf of the account to pay for gas
     */
    function setUp() public {
        counter = new Counter();
        entryPoint = new EntryPoint();
        accountFactory = new P256AccountFactory(entryPoint);
        account = accountFactory.createAccount(publicKey);
        vm.deal(richard, 1e50);
        vm.prank(richard);
        entryPoint.depositTo{value: 1e18}(address(account));
    }

    /**
     * Check the account was created correctly with the correct parameters
     */
    function testCreation() public view {
        assertEq(account.getNonce(), 0);
        assertEq(account.publicKey(), publicKey);
    }

    /**
     * Create a userOp that increments the counter and send it through the entrypoint
     */
    function testUserOpE2ESuccess() public {
        assertEq(counter.number(), 0);
        bytes memory incrementCounterCallData = abi.encodeWithSelector(
            account.execute.selector,
            address(counter),
            0,
            abi.encodeWithSelector(counter.increment.selector)
        );
        UserOperation[] memory userOps = new UserOperation[](1);
        userOps[0] = _createUserOp(incrementCounterCallData, validSignature);
        entryPoint.handleOps(userOps, payable(richard));
        assertEq(counter.number(), 1);
    }

    /**
     * Create a userOp that fails to increments the counter and send it through the entrypoint, because of invalid signature
     */
    function testUserOpE2EFailure() public {
        bytes memory invalidSignature = hex"";
        bytes memory incrementCounterCallData = abi.encodeWithSelector(
            account.execute.selector,
            address(counter),
            0,
            abi.encodeWithSelector(counter.increment.selector)
        );
        UserOperation[] memory userOps = new UserOperation[](1);
        userOps[0] = _createUserOp(incrementCounterCallData, invalidSignature);
        vm.expectRevert();
        entryPoint.handleOps(userOps, payable(richard));
    }

    // TODO: HAVE TO REPLACE THIS

    bytes validSignature =
        hex"29f998a79ad54d561f202d10c32031f607f7fa931b77f5cbf89b38076592be9a0895aa5203308541af5b2e0dc22bef9cec3ad08e4d9c9b1bbef7324df6fe45a81115c7b29d8cffe93b17927d06bd9487f341ceae76d61c23acdfda419065e6352c4795e2b426fdfd9249004b4aa2e64c677788ef2188e67a6732983ad5da2c462628d45d3a082a46f41ed0c6a2dde9bdaab5983bf2869f25b21afe2e4c2110390d60b846f86cd6ee2483995f1ccc8618eb9009c1239a954d5d8e07394f98934829ec28d4bfded92e01afc92c3beb0461742d38123f175998b6bd80e96bb2cd210bf330f9d106ccff8e4ecd9ae2efe546ef2bd7a4c0a43af444591399e5cd7dea0ddbec375fa3bd57180f1474856c330844b99beb8bbfd2f7b667e679374af30c280832199f21e17a27a23ad86399b7c715770307db342b6c19523610c48248692e145515fa73e001aa804fae90f8363c5a3c80e4a7bd717d6f08e0bea701283028eae1bbdd2c195d5c538eaad1f827ecade6e4b2d04a602c03f9048b0e9378bd1d9dd34ec7cd389f6066ca7e29b60ff6c223a77f5e285b22759ee83a2474c88b2402e45816b14132c60b9463f9f2fe743c1c368a47615c3f770fd656e8fdfc762bf17128729f6efb5bd05c666cb2e3bbf2598797c9a451679cdcb3f02594756e08633ef9fa3b36412b29765b96191e4006350af9e136997e14f9a89b632094e71d1e68ceccfa8d5ecf9b9446ffd1aff91168f78b192b9c12bbc23d5e0474105613f45aec77260bfe5637dd2eb1eaabcf0e92c317940a3ddbd6d50e67ada8f67e185e8b698d53b352d0a64e10404fe44b9a85b1898ac4712a389224029734a11a1d362d976d6bda11fd56ac84827c660077e2f893bf7a2b18a0217087642ed4690d26b838a549e1940455aa2627f171864bc7083dc5673b06f17fb9147840867b06c33f55e2a42aa487cb5b0604b509246ff8f68978ac8b66c55b661f4a45d0e00fba845525372b874cea2767e431fe03dd36c2af563bf94cb9ecd0d2dc48dc2a200b151295886090d20b567806f7c6e3c2b4147d44cf395c8766a4cc3ddc52d5245368fe43088cbd2f574b24d9fcd9d2ed519efa83a7958296dbd91629b11a3703b7ab2d0b8223d7128edd8043e85661d8928b5929fd18da11d54c5c515868c32fe40d3bb45e2967dc616df4fd3fef2c3f72c13f5eb7d8516c43d604b1d5cf2224a177344796b41eeeab8cca7c1f182b66e1025efaa76f88a406fee98ea8e9392d54b900e3c158fca9bdc5498d1ccfc8873d5f61b648c73145961b3a16390e860e1bb2fe95e5e2a92fe74f35317bd2a64da8c52a1a9eb807ca689a270517dd320f74e37dfcf3c9e8b785a77457a01df6bb626ccbec32b6ad193fdc8ec7a3a9bb105eb0d726d6293ac555ffb339760f8660c6f9e8480c565e7324933015d7d3c70746939df0f749ffeb12087425c26975ca212b507610c83e490d6e583d7869991ddda9931e6d508f8232eb650b8847930c8851e3912dff5b1d1605d7e3c1e8322d5d99670916c19d6597aa80b91e0ef2371745cd31cc42b13fcfa562ff30397f2aeed2c175358b657a721c17de12bedb350d58683001fc330afeea155488248919c857f0d216cd3d05662f79d42bfb63f93441eee1a07ba7b0058fa20b9e0d232e8398eb0b0454cafbd2fa501797cc43a05fb25609e4c2e86e6a5f5dff40e17512fa1f8db6235c1f2a35c3b87b62b4fa54d598f9fda14493cc290972ce9f90531a0b90534f982fe696408dd56474e2fc10b5eeed0939d6edb41d28bd4260f1d3047e9148a846fad8a909c64b67cf3dc0146a95f53d64dc4f7d59a799732414f118656c36ecd754a6e71b6e66ceb8367bb668a73a059d8abee5ad9f4eabf4c5592eeca4b396bb47333b7f7825d33a65134fe2d6d7d0289f9216998a321f95f2831b42eccbb297611dfcf7bb76bf54534123814b66f9acc77fed96780fef4705de2d4557333a7438b2851fe0bd7432ef1826afd39873a064788c26c05afb1f6acd23a0b37c1054d1be54c78bdd823e42c85043f91ec3c32ccd72bf08cf7fa8a47c28bdaafe20843fef3b3397428cef3794b03b9148e993b7ef8c8ee45bef6a181c27b3c2c46010595a6f6631a36b3b519f9136d4be2cd805a99f26dbdd1956ccba161c633f4e0afe17d2118364d66ded970fe925508f95eef5a8c5a2c8076128c127368f1ece7f766f49d51b179fed1fcd8690a47d03f2bd588bd826500e68cd6e1b2910465ea372f8f601e926c143137a588c5ce4d9eb5fda9bf0910eedf3d11c29ddbefd64745f8225ccc1a08be570560452552a84ef332958ec7d86641e4a652be177680396a72eee29f48b30e439ea654d319c3599166a1d593943752a232e17c170baafff14b5b775d7d0d30a3335e162a9fcc28f30f0496733ac8a73e2f2279abce417264607348b22f158eee77a26b73eacfeaf4355a2edb48a4a04a69929238960c736a57e796a5a4ac083c80e34e2cc0461b564868847a6546bc285a314503720f252764d12e0b5590e2e46b8fec06a20da5a5e8fc5e1ccbc3b2bc3ca146656b8300794597f0b87bf9d2eb422fe5513653d41323780e99a1be9a41dcb0bfb714f59e20291a8b805701f6e435cb8e73370b1253c3ec891fe4116040b0d0cd8a7ac0a6727a532cc194f5cbb9cfbfeb4d62f9b497a8b1966c18abdcfd55f1390eedd2297804cc244b25b7e393b1b8b462e502a69da1a271303a659454c5302e0aa9b3ef23e545ea521627df794bbb9ee19fdb57768a08c732ecdeb34189d2809795980d21b95a2f9d0c749100835496bf275ea7d743e4a7b8934fa4478d325de51b68af9d95d098f4540163a5be3e6c2669772f80685aff588738d5f6f7a1e8799d581605ad52efa87b498ccea2149298b0b25f49e54789fbfe1341d1e2f02c0331954b5bb5fdfccd635da25d32c7c5fce3ad1ed1985056b5f970db2471100152fe7976a1705d08e352254025f35d99b3ef397869067eaef3e1465d53c65122e2e7d3a202e7530b79bf7732447ce9068bc7fe2e251a59b590db402bcc115173a8ff64a04e2e02af6f00cfb70e4694b3f0608b85d917bedc9fb26191b49c213777ccdaee976412d326555b43335e28029b403741fc5024e23fd728485c538259eedc5b53d730ed34f8d23b27bb2a03dcf19f09fa493db193b6a3fe94938f423844733f3913b8bba732ba2456300ad72a52243c47c7d558106f42dea19032e1383abf6df27e38b2a4215ba88d1982099355cda05a2aa9e30a7da9c732902d818f04018b716975721599e11efd78e28c19ee508955c3f276edf2d58de2e3cfb2b802812ebfd3cc54cad11b78c27700cc2f184312b0aae93c16c90f51915e500109c0b4fc83f42d1d288a89b7c6c51f9fc41b258d99cc6d93b9d947df86ff9142f32c35ca02a67e9e2eebef3f467d085e03c5d47862678271075eeb8d1cbd08417b8799e11c592f947e579451f1027b3d8515d9f36236a43d6b15fbe8fbaf5820a151a0c905e61c1e6b098c99341d5ae0b24028d57567682f70faaddc936cad00f8e150818e7a3bcd46b0f51a7821e862e264f2b0cf2ac7ae791f1028ab8942526222fef01f17b71531ff140f0224378d369697df067bb7ec2e46d945273394906df43dcb812e7ea06e486de959b0bd4c7d1334010cb7be83f4c7c3cab8996072d5044c058e43f5700ba7f287d542d4a1daa7077b6496d0b6eedc129778c10b72f3737d49033de9a7b6f7272d1ad2317cb5aa706fa8649e10d723a7101d8dd74246ea0ded2552e6b85f959b9fb9425878cf17ec529a89b8af35042edb0c7e1a9";
}
