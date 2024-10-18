// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console, Vm} from "forge-std/Test.sol";
import "../src/Types.sol";
import {WormholeRelayer} from "../src/WormholeRelayer.sol";
import {Wormhole, Structs} from "../src/Wormhole.sol";
import {DeliveryProvider} from "../src/DeliveryProvider.sol";

contract WHTest is Test {
    WormholeRelayer public wr_eth;
    Wormhole public w_eth;
    DeliveryProvider public dp_eth;

    WormholeRelayer public wr_bsc;
    Wormhole public w_bsc;
    DeliveryProvider public dp_bsc;

    uint256[] public pks;

    function gen_guardian_set(
        uint32 expirationTime
    ) private view returns (Structs.GuardianSet memory gs) {
        gs.expirationTime = expirationTime;
        gs.keys = new address[](pks.length);
        for (uint256 i = 0; i < pks.length; i++) {
            gs.keys[i] = vm.addr(pks[i]);
        }
    }

    function gen_sigs(
        bytes32 h
    ) private view returns (Structs.Signature[] memory sigs) {
        sigs = new Structs.Signature[](pks.length);
        for (uint256 i = 0; i < pks.length; i++) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(pks[i], h);
            sigs[i].guardianIndex = uint8(i);
            sigs[i].r = r;
            sigs[i].s = s;
            sigs[i].v = v;
        }
    }

    function encodeLastPartWithHash(
        uint32 timestamp,
        uint32 nonce,
        uint16 emitterChainId,
        bytes32 emitterAddress,
        uint64 sequence,
        uint8 consistencyLevel,
        bytes memory payload
    ) private pure returns (bytes32 hash, bytes memory enc) {
        enc = abi.encodePacked(
            timestamp,
            nonce,
            emitterChainId,
            emitterAddress,
            sequence,
            consistencyLevel,
            payload
        );
        hash = keccak256(abi.encodePacked(keccak256(enc)));
    }

    function encodeVM(
        uint8 version,
        uint32 timestamp,
        uint32 nonce,
        uint16 emitterChainId,
        bytes32 emitterAddress,
        uint64 sequence,
        uint8 consistencyLevel,
        bytes memory payload,
        uint32 guardianSetIndex,
        Structs.Signature[] memory signatures
    ) public pure returns (bytes memory enc) {
        // Start encoding with the version (1 byte)
        enc = abi.encodePacked(version); // uint8: 1 byte

        // Append guardianSetIndex (uint32: 4 bytes)
        enc = abi.encodePacked(enc, guardianSetIndex);

        // Append the length of signatures (uint8: 1 byte)
        uint8 signaturesLength = uint8(signatures.length);
        enc = abi.encodePacked(enc, signaturesLength);

        // Encode each signature
        for (uint i = 0; i < signatures.length; i++) {
            Structs.Signature memory sig = signatures[i];

            // Adjust v to be (v - 27), as per the Python code
            uint8 vMinus27 = sig.v - 27;

            enc = abi.encodePacked(
                enc,
                sig.guardianIndex, // uint8: 1 byte
                sig.r, // bytes32: 32 bytes
                sig.s, // bytes32: 32 bytes
                vMinus27 // uint8: 1 byte
            );
        }

        // Encode the last part and compute the hash
        (, bytes memory lastPart) = encodeLastPartWithHash(
            timestamp,
            nonce,
            emitterChainId,
            emitterAddress,
            sequence,
            consistencyLevel,
            payload
        );

        // Append the last part to the encoding
        enc = abi.encodePacked(enc, lastPart);
    }

    function setUp() public {
        for (uint256 i = 1; i <= 19; i++) {
            pks.push(i);
        }

        w_eth = new Wormhole();
        w_eth.setChainIDs(2, 1);
        w_eth.initialize();
        dp_eth = new DeliveryProvider();
        dp_eth.setAssetConversionBufferPub(4, 0, 1);
        dp_eth.setAssetConversionBufferPub(2, 0, 1);
        dp_eth.setPriceInfoPub(2, GasPrice.wrap(1), WeiPrice.wrap(1));
        dp_eth.setPriceInfoPub(4, GasPrice.wrap(1), WeiPrice.wrap(1));
        dp_eth.setChainIdPub(2);
        dp_eth.setMaximumBudgetPub(4, Wei.wrap(1e18));
        dp_eth.setChainSupportedPub(4, true);
        wr_eth = new WormholeRelayer(address(w_eth));
        wr_eth.initialize(address(dp_eth));

        w_bsc = new Wormhole();
        w_bsc.setChainIDs(4, 56);
        w_bsc.initialize();
        dp_bsc = new DeliveryProvider();
        dp_bsc.setAssetConversionBufferPub(4, 0, 1);
        dp_bsc.setAssetConversionBufferPub(2, 0, 1);
        dp_bsc.setPriceInfoPub(2, GasPrice.wrap(1), WeiPrice.wrap(1));
        dp_bsc.setPriceInfoPub(4, GasPrice.wrap(1), WeiPrice.wrap(1));
        dp_bsc.setChainIdPub(4);
        dp_bsc.setMaximumBudgetPub(2, Wei.wrap(1e18));
        dp_bsc.setChainSupportedPub(2, true);
        wr_bsc = new WormholeRelayer(address(w_bsc));
        wr_bsc.initialize(address(dp_bsc));
    }

    function test_querying_fees() public view {
        uint16 targetChain = 4;
        TargetNative receiverValue = TargetNative.wrap(0);
        Gas gasLimit = Gas.wrap(100_000);

        // Estimate fee eth -> bsc
        (LocalNative estimatedFee, ) = wr_eth.quoteEVMDeliveryPrice(
            targetChain,
            receiverValue,
            gasLimit
        );

        assertEq(
            LocalNative.unwrap(estimatedFee),
            Gas.unwrap(gasLimit) + TargetNative.unwrap(receiverValue)
        );

        targetChain = 2;
        receiverValue = TargetNative.wrap(100);
        gasLimit = Gas.wrap(200_000);

        // Estimate fee bsc -> eth
        (estimatedFee, ) = wr_bsc.quoteEVMDeliveryPrice(
            targetChain,
            receiverValue,
            gasLimit
        );
        assertEq(
            LocalNative.unwrap(estimatedFee),
            Gas.unwrap(gasLimit) + TargetNative.unwrap(receiverValue)
        );
    }

    function test_sending_from_source() public {
        uint64 sequence;
        uint256 g;

        // ETH ------------------------------------------------------------
        uint16 targetChain = 4;
        address targetAddress = 0xaD5db72456E417bb51d9e89425e6B2b9602dfc78;
        bytes memory payload = abi.encode(msg.sender, 100);
        TargetNative receiverValue = TargetNative.wrap(0);
        Gas gasLimit = Gas.wrap(100_000);

        for (uint256 i = 0; i < 3; i++) {
            g = gasleft();
            sequence = wr_eth.sendPayloadToEvm{value: 100_000}(
                targetChain,
                targetAddress,
                payload,
                receiverValue,
                gasLimit
            );
            console.log("ETH (index, gasUsed) = ", i, g - gasleft());
            assertEq(sequence, i);
        }

        // BSC ------------------------------------------------------------
        targetChain = 2;
        targetAddress = 0x7c8F69947FD70615170295d806e0fC99FfcA7b1E;
        payload = abi.encode(msg.sender, 100);
        receiverValue = TargetNative.wrap(0);
        gasLimit = Gas.wrap(100_000);

        for (uint256 i = 0; i < 3; i++) {
            g = gasleft();
            sequence = wr_bsc.sendPayloadToEvm{value: 100_000}(
                targetChain,
                targetAddress,
                payload,
                receiverValue,
                gasLimit
            );
            console.log("BSC (index, gasUsed) = ", i, g - gasleft());
            assertEq(sequence, i);
        }
    }

    function test_getting_logs_and_print() public {
        uint64 sequence;

        // Logging ------------------------------------------------------------
        uint16 targetChain = 4;
        address targetAddress = 0xaD5db72456E417bb51d9e89425e6B2b9602dfc78;
        bytes memory payload = abi.encode(msg.sender, 100);
        TargetNative receiverValue = TargetNative.wrap(0);
        Gas gasLimit = Gas.wrap(100_000);

        vm.recordLogs();
        sequence = wr_eth.sendPayloadToEvm{value: 100_000}(
            targetChain,
            targetAddress,
            payload,
            receiverValue,
            gasLimit
        );
        Vm.Log[] memory logs = vm.getRecordedLogs();
        for (uint256 i = 0; i < logs.length; i++) {
            console.log("Log emitted from contract:", logs[i].emitter);
            console.logBytes32(logs[i].topics[0]);
            console.logBytes(logs[i].data);
        }
    }

    function test_deriving_pk_and_sign_and_verify() public view {
        bytes32 h = keccak256(
            abi.encodePacked("some random message to be signed by the signers")
        );
        for (uint256 i = 0; i < pks.length; i++) {
            uint256 pk = pks[i];
            address signerAddress = vm.addr(pk);
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, h);
            assertEq(signerAddress, ecrecover(h, v, r, s));
        }
    }

    function test_verifying_sigs_by_wh_core() public view {
        bytes32 h = keccak256(
            abi.encodePacked("some random message to be signed by the signers")
        );
        Structs.GuardianSet memory guardianSet = gen_guardian_set(0);
        Structs.Signature[] memory signatures = gen_sigs(h);
        (bool valid, string memory reason) = w_eth.verifySignatures(
            h,
            signatures,
            guardianSet
        );
        assertEq(valid, true);
        assertEq(reason, "");
    }

    function test_encodeLastPartWithHash() public pure {
        (bytes32 h, ) = encodeLastPartWithHash(
            1720525446,
            0,
            4,
            bytes32(
                uint256(uint160(0x80aC94316391752A193C1c47E27D382b507c93F3))
            ),
            6680,
            15,
            hex"012712000000000000000000000000f2bc73502283fcac4b047dfe45366d8744daac5b000000d99945ff1000000000000000000000000066cb5a992570ef01b522bc59a056a64a84bd0aaa0000000000000000000000008b715eaf61a7ddf61c67d5d46687c796d1f47146009100000000000000000000000000000000000000000000000000000000000000030000000000000000000000009eb0cb7841e55d3d9caf49df9c61d5d857d17c82004f994e54540800000000000186a00000000000000000000000000b15635fcf5316edfd2a9a0b0dc3700aea4d09e6000000000000000000000000418629cfb2f5616ca47e3febfcf28c43321a1a4e2712000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007a1200000000000000000000000000000000000000000000000000000000000e46e7d2712000000000000000000000000418629cfb2f5616ca47e3febfcf28c43321a1a4e0000000000000000000000007a0a53847776f7e94cc35742971acb2217b0db8100000000000000000000000060a86b97a7596ebfd25fb769053894ed0d9a83660000000000000000000000003a84364d27ed3d16022da0f603f3e0f74826c70700"
        );
        assertEq(
            h,
            0xaf22a57cc835b0847c0eb8ad84a9d4c4743e49fc6eaa1355f603d1a66373626d
        );
    }

    function test_encodeVM() public view {
        uint8 version = 1;
        uint32 timestamp = 1720525446;
        uint32 nonce = 0;
        uint16 emitterChainId = 4;
        bytes32 emitterAddress = 0x00000000000000000000000080ac94316391752a193c1c47e27d382b507c93f3;
        uint64 sequence = 6680;
        uint8 consistencyLevel = 15;
        bytes
            memory payload = hex"012712000000000000000000000000f2bc73502283fcac4b047dfe45366d8744daac5b000000d99945ff1000000000000000000000000066cb5a992570ef01b522bc59a056a64a84bd0aaa0000000000000000000000008b715eaf61a7ddf61c67d5d46687c796d1f47146009100000000000000000000000000000000000000000000000000000000000000030000000000000000000000009eb0cb7841e55d3d9caf49df9c61d5d857d17c82004f994e54540800000000000186a00000000000000000000000000b15635fcf5316edfd2a9a0b0dc3700aea4d09e6000000000000000000000000418629cfb2f5616ca47e3febfcf28c43321a1a4e2712000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007a1200000000000000000000000000000000000000000000000000000000000e46e7d2712000000000000000000000000418629cfb2f5616ca47e3febfcf28c43321a1a4e0000000000000000000000007a0a53847776f7e94cc35742971acb2217b0db8100000000000000000000000060a86b97a7596ebfd25fb769053894ed0d9a83660000000000000000000000003a84364d27ed3d16022da0f603f3e0f74826c70700";
        uint32 guardianSetIndex = 0;
        (bytes32 h, ) = encodeLastPartWithHash(
            timestamp,
            nonce,
            emitterChainId,
            emitterAddress,
            sequence,
            consistencyLevel,
            payload
        );
        Structs.Signature[] memory signatures = gen_sigs(h);
        bytes memory enc = encodeVM(
            version,
            timestamp,
            nonce,
            emitterChainId,
            emitterAddress,
            sequence,
            consistencyLevel,
            payload,
            guardianSetIndex,
            signatures
        );

        Structs.VM memory vm = w_eth.parseVM(enc);
        assertEq(vm.version, version);
        assertEq(vm.timestamp, timestamp);
        assertEq(vm.nonce, nonce);
        assertEq(vm.emitterChainId, emitterChainId);
        assertEq(vm.emitterAddress, emitterAddress);
        assertEq(vm.sequence, sequence);
        assertEq(vm.consistencyLevel, consistencyLevel);
        assertEq(keccak256(vm.payload), keccak256(payload));
        assertEq(vm.guardianSetIndex, guardianSetIndex);
        assertEq(
            keccak256(abi.encode(vm.signatures)),
            keccak256(abi.encode(signatures))
        );
        assertEq(vm.hash, h);
    }
}
