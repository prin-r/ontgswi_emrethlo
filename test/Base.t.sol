// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console, Vm} from "forge-std/Test.sol";
import "../src/Types.sol";
import {WormholeRelayer, IWormholeRelayerDelivery} from "../src/WormholeRelayer.sol";
import {Wormhole, Structs} from "../src/Wormhole.sol";
import {WormholeCom, StructsCom} from "../src/WormholeCom.sol";
import {DeliveryProvider} from "../src/DeliveryProvider.sol";
import {CrossChainToken} from "../src/CCToken.sol";

contract WHTest is Test {
    address public alice;
    uint256 public constant N =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    uint8 public constant parity = 28;
    uint256 public constant px =
        0x5fe055a80305da76a999c83a4bc19f26b498bb2424874138eccd8dee9a2b5c4e;
    uint256 public constant comSk =
        0x2222222222222222222222222222222222222222222222222222222222222200;

    CrossChainToken public cct_eth;
    WormholeRelayer public wr_eth;
    WormholeRelayer public wrcom_eth;
    Wormhole public w_eth;
    WormholeCom public wcom_eth;
    DeliveryProvider public dp_eth;

    CrossChainToken public cct_bsc;
    WormholeRelayer public wr_bsc;
    WormholeRelayer public wrcom_bsc;
    Wormhole public w_bsc;
    WormholeCom public wcom_bsc;
    DeliveryProvider public dp_bsc;

    uint256[] public pks;

    function genGuardianSet(
        uint32 expirationTime
    ) private view returns (Structs.GuardianSet memory gs) {
        gs.expirationTime = expirationTime;
        gs.keys = new address[](pks.length);
        for (uint256 i = 0; i < pks.length; i++) {
            gs.keys[i] = vm.addr(pks[i]);
        }
    }

    function genMultiSigs(
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
        enc = abi.encodePacked(version);
        enc = abi.encodePacked(enc, guardianSetIndex);
        enc = abi.encodePacked(enc, uint8(signatures.length));

        for (uint i = 0; i < signatures.length; i++) {
            Structs.Signature memory sig = signatures[i];
            enc = abi.encodePacked(
                enc,
                sig.guardianIndex,
                sig.r,
                sig.s,
                sig.v - 27
            );
        }

        (, bytes memory lastPart) = encodeLastPartWithHash(
            timestamp,
            nonce,
            emitterChainId,
            emitterAddress,
            sequence,
            consistencyLevel,
            payload
        );

        enc = abi.encodePacked(enc, lastPart);
    }

    function encodeVMCom(
        uint8 version,
        uint32 timestamp,
        uint32 nonce,
        uint16 emitterChainId,
        bytes32 emitterAddress,
        uint64 sequence,
        uint8 consistencyLevel,
        bytes memory payload,
        uint32 guardianSetIndex
    ) public view returns (bytes32 h, bytes memory enc) {
        bytes memory lastPart;
        enc = abi.encodePacked(version, guardianSetIndex);
        (h, lastPart) = encodeLastPartWithHash(
            timestamp,
            nonce,
            emitterChainId,
            emitterAddress,
            sequence,
            consistencyLevel,
            payload
        );
        (address rAddress, uint256 s) = genSigCom(h);
        enc = abi.encodePacked(
            enc,
            bytes12(0),
            rAddress,
            parity,
            bytes32(px),
            s
        );
        enc = abi.encodePacked(enc, lastPart);
    }

    function genSigCom(
        bytes32 h
    ) private view returns (address rAddress, uint256 s) {
        uint256 k = uint256(keccak256(abi.encode(h))) % N;
        rAddress = vm.addr(k);
        uint256 c = uint256(
            keccak256(abi.encodePacked(rAddress, parity, px, h))
        );
        s = addmod(k, mulmod(c, comSk, N), N);
    }

    function setUp() public {
        alice = address(0xaa);
        vm.label(alice, "Alice");
        vm.deal(alice, 100 ether);

        address[] memory bridges = new address[](2);

        for (uint256 i = 1; i <= 19; i++) {
            pks.push(i);
        }

        wcom_eth = new WormholeCom();
        wcom_eth.setChainIDs(2, 1);
        wcom_eth.initialize();
        wcom_eth.setGuardianSet(parity, 0, px, type(uint32).max);

        w_eth = new Wormhole();
        w_eth.setChainIDs(2, 1);
        w_eth.initialize();
        w_eth.setGuardianSet(0, genGuardianSet(type(uint32).max));

        dp_eth = new DeliveryProvider();
        dp_eth.setMultiple(2, 4);

        wr_eth = new WormholeRelayer(address(w_eth));
        wr_eth.initialize(address(dp_eth));

        wrcom_eth = new WormholeRelayer(address(wcom_eth));
        wrcom_eth.initialize(address(dp_eth));

        bridges[0] = address(wr_eth);
        bridges[1] = address(wrcom_eth);
        cct_eth = new CrossChainToken("CrossChainToken", "CCT", bridges);

        wcom_bsc = new WormholeCom();
        wcom_bsc.setChainIDs(4, 56);
        wcom_bsc.initialize();
        wcom_bsc.setGuardianSet(parity, 0, px, type(uint32).max);

        w_bsc = new Wormhole();
        w_bsc.setChainIDs(4, 56);
        w_bsc.initialize();
        w_bsc.setGuardianSet(0, genGuardianSet(type(uint32).max));

        dp_bsc = new DeliveryProvider();
        dp_bsc.setMultiple(4, 2);

        wr_bsc = new WormholeRelayer(address(w_bsc));
        wr_bsc.initialize(address(dp_bsc));

        wrcom_bsc = new WormholeRelayer(address(wcom_bsc));
        wrcom_bsc.initialize(address(dp_bsc));

        bridges[0] = address(wr_bsc);
        bridges[1] = address(wrcom_bsc);
        cct_bsc = new CrossChainToken("CrossChainToken", "CCT", bridges);

        wr_eth.setEmitter(uint16(4), bytes32(uint256(uint160(address(w_bsc)))));
        wrcom_eth.setEmitter(
            uint16(4),
            bytes32(uint256(uint160(address(wcom_bsc))))
        );
        cct_eth.registerContract(4, address(cct_bsc));

        wr_bsc.setEmitter(uint16(2), bytes32(uint256(uint160(address(w_eth)))));
        wrcom_bsc.setEmitter(
            uint16(2),
            bytes32(uint256(uint160(address(wcom_eth))))
        );
        cct_bsc.registerContract(2, address(cct_eth));

        cct_eth.mint(alice, 200);
    }

    function test_verify_sig_com() public view {
        bytes32 h = keccak256(abi.encode("hello"));
        (address rAddress, uint256 s) = genSigCom(h);
        bool valid;
        string memory reason;
        // ETH
        (valid, reason) = wcom_eth.verifySignatures(
            rAddress,
            parity,
            px,
            s,
            h,
            wcom_eth.getGuardianSet(0)
        );
        assertEq(valid, true);
        assertEq(reason, "");

        // BSC
        (valid, reason) = wcom_bsc.verifySignatures(
            rAddress,
            parity,
            px,
            s,
            h,
            wcom_eth.getGuardianSet(0)
        );
        assertEq(valid, true);
        assertEq(reason, "");
    }

    function test_com_verifyVM() public {
        bool valid;
        string memory reason;
        StructsCom.VM memory vm;
        vm.version = 1;
        vm.timestamp = 1720525446;
        vm.nonce = 0;
        vm.emitterChainId = 4;
        vm
            .emitterAddress = 0x00000000000000000000000080ac94316391752a193c1c47e27d382b507c93f3;
        vm.sequence = 6680;
        vm.consistencyLevel = 15;
        vm
            .payload = hex"012712000000000000000000000000f2bc73502283fcac4b047dfe45366d8744daac5b000000d99945ff1000000000000000000000000066cb5a992570ef01b522bc59a056a64a84bd0aaa0000000000000000000000008b715eaf61a7ddf61c67d5d46687c796d1f47146009100000000000000000000000000000000000000000000000000000000000000030000000000000000000000009eb0cb7841e55d3d9caf49df9c61d5d857d17c82004f994e54540800000000000186a00000000000000000000000000b15635fcf5316edfd2a9a0b0dc3700aea4d09e6000000000000000000000000418629cfb2f5616ca47e3febfcf28c43321a1a4e2712000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007a1200000000000000000000000000000000000000000000000000000000000e46e7d2712000000000000000000000000418629cfb2f5616ca47e3febfcf28c43321a1a4e0000000000000000000000007a0a53847776f7e94cc35742971acb2217b0db8100000000000000000000000060a86b97a7596ebfd25fb769053894ed0d9a83660000000000000000000000003a84364d27ed3d16022da0f603f3e0f74826c70700";
        vm.guardianSetIndex = 0;
        vm
            .hash = 0xaf22a57cc835b0847c0eb8ad84a9d4c4743e49fc6eaa1355f603d1a66373626d;
        vm.px = px;
        vm.parity = parity;
        (vm.rAddress, vm.s) = genSigCom(vm.hash);

        (valid, reason) = wcom_eth.verifyVM(vm);
        assertEq(valid, true);
        assertEq(reason, "");
    }

    function test_com_parseAndVerifyVM() public {
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

        (bytes32 h, bytes memory enc) = encodeVMCom(
            version,
            timestamp,
            nonce,
            emitterChainId,
            emitterAddress,
            sequence,
            consistencyLevel,
            payload,
            guardianSetIndex
        );

        assertEq(
            h,
            0xaf22a57cc835b0847c0eb8ad84a9d4c4743e49fc6eaa1355f603d1a66373626d
        );
        (StructsCom.VMN memory vm, bool valid, string memory reason) = wcom_eth
            .parseAndVerifyVM(enc);

        assertEq(valid, true);
        assertEq(reason, "");

        assertEq(vm.version, version);
        assertEq(vm.timestamp, timestamp);
        assertEq(vm.nonce, nonce);
        assertEq(vm.emitterChainId, emitterChainId);
        assertEq(vm.emitterAddress, emitterAddress);
        assertEq(vm.sequence, sequence);
        assertEq(vm.consistencyLevel, consistencyLevel);
        assertEq(keccak256(vm.payload), keccak256(payload));
        assertEq(vm.guardianSetIndex, guardianSetIndex);
        assertEq(vm.hash, h);
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
        bytes memory payload = abi.encode(msg.sender, 12345678);
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
            if (logs[i].emitter == address(w_eth)) {
                (uint64 s2, uint32 n, bytes memory p, uint8 c) = abi.decode(
                    logs[i].data,
                    (uint64, uint32, bytes, uint8)
                );
                console.log("sender = ");
                console.logBytes32(logs[i].topics[1]);
                console.log("sequence = ", s2);
                console.log("nonce = ", n);
                console.logBytes(p);
                console.log("consistencyLevel = ", c);
            }
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
        Structs.GuardianSet memory guardianSet = genGuardianSet(0);
        Structs.Signature[] memory signatures = genMultiSigs(h);
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
        Structs.Signature[] memory signatures = genMultiSigs(h);
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

    function test_verifyVM() public {
        Structs.VM memory vm;
        vm.version = 1;
        vm.timestamp = 1720525446;
        vm.nonce = 0;
        vm.emitterChainId = 4;
        vm
            .emitterAddress = 0x00000000000000000000000080ac94316391752a193c1c47e27d382b507c93f3;
        vm.sequence = 6680;
        vm.consistencyLevel = 15;
        vm
            .payload = hex"012712000000000000000000000000f2bc73502283fcac4b047dfe45366d8744daac5b000000d99945ff1000000000000000000000000066cb5a992570ef01b522bc59a056a64a84bd0aaa0000000000000000000000008b715eaf61a7ddf61c67d5d46687c796d1f47146009100000000000000000000000000000000000000000000000000000000000000030000000000000000000000009eb0cb7841e55d3d9caf49df9c61d5d857d17c82004f994e54540800000000000186a00000000000000000000000000b15635fcf5316edfd2a9a0b0dc3700aea4d09e6000000000000000000000000418629cfb2f5616ca47e3febfcf28c43321a1a4e2712000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007a1200000000000000000000000000000000000000000000000000000000000e46e7d2712000000000000000000000000418629cfb2f5616ca47e3febfcf28c43321a1a4e0000000000000000000000007a0a53847776f7e94cc35742971acb2217b0db8100000000000000000000000060a86b97a7596ebfd25fb769053894ed0d9a83660000000000000000000000003a84364d27ed3d16022da0f603f3e0f74826c70700";
        vm.guardianSetIndex = 0;
        vm
            .hash = 0xaf22a57cc835b0847c0eb8ad84a9d4c4743e49fc6eaa1355f603d1a66373626d;
        vm.signatures = genMultiSigs(vm.hash);
        (bool valid, ) = w_eth.verifyVM(vm);
        assertEq(valid, true);
    }

    function test_parseAndVerifyVM() public {
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
        Structs.Signature[] memory signatures = genMultiSigs(h);
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

        (Structs.VM memory vm, bool valid, ) = w_eth.parseAndVerifyVM(enc);
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
        assertEq(valid, true);
    }

    function test_send_and_deliver() public {
        // Send ------------------------------------------------------------
        uint16 targetChain = 4;
        address targetAddress = 0xaD5db72456E417bb51d9e89425e6B2b9602dfc78;
        TargetNative receiverValue = TargetNative.wrap(0);
        Gas gasLimit = Gas.wrap(100_000);

        vm.recordLogs();
        uint64 sequence = wr_eth.sendPayloadToEvm{value: 100_000}(
            targetChain,
            targetAddress,
            abi.encode(msg.sender, 12345678),
            receiverValue,
            gasLimit
        );
        // Send ------------------------------------------------------------

        // off-chain ------------------------------------------------------------
        Vm.Log[] memory logs = vm.getRecordedLogs();
        bytes memory logData;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].emitter == address(w_eth)) {
                logData = logs[i].data;
            }
        }

        (
            uint64 s,
            uint32 nonce,
            bytes memory instruction,
            uint8 consistencyLevel
        ) = abi.decode(logData, (uint64, uint32, bytes, uint8));
        assertEq(sequence, s);
        assertEq(nonce, 0);

        (bytes32 h, ) = encodeLastPartWithHash(
            uint32(1720525446),
            nonce,
            w_eth.chainId(),
            bytes32(uint256(uint160(address(w_eth)))),
            sequence,
            consistencyLevel,
            instruction
        );
        Structs.Signature[] memory signatures = genMultiSigs(h);
        bytes memory enc = encodeVM(
            uint8(1),
            uint32(1720525446),
            nonce,
            w_eth.chainId(),
            bytes32(uint256(uint160(address(w_eth)))),
            sequence,
            consistencyLevel,
            instruction,
            uint32(0),
            signatures
        );
        // off-chain ------------------------------------------------------------

        // Deliver ------------------------------------------------------------
        wr_bsc.deliver{value: 100000}(
            new bytes[](0),
            enc,
            payable(address(0)),
            hex""
        );

        logs = vm.getRecordedLogs();
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].emitter == address(wr_bsc)) {
                assertEq(logs[i].topics.length, 4);
                assertEq(
                    logs[i].topics[0],
                    keccak256(
                        abi.encodePacked(
                            "Delivery(address,uint16,uint64,bytes32,uint8,uint256,uint8,bytes,bytes)"
                        )
                    )
                );
                assertEq(
                    bytes32(uint256(uint160(targetAddress))),
                    logs[i].topics[1]
                );
                assertEq(
                    bytes32(uint256(uint16(w_eth.chainId()))),
                    logs[i].topics[2]
                );
                assertEq(bytes32(uint256(sequence)), logs[i].topics[3]);
                (bytes32 deliveryVaaHash, uint8 status, , , , ) = abi.decode(
                    logs[i].data,
                    (bytes32, uint8, uint256, uint8, bytes, bytes)
                );
                assertEq(deliveryVaaHash, h);
                assertEq(
                    status,
                    uint8(IWormholeRelayerDelivery.DeliveryStatus.SUCCESS)
                );
            }
        }
        // Deliver ------------------------------------------------------------
    }

    function test_send_com_and_deliver_com() public {
        // Send ------------------------------------------------------------
        uint16 targetChain = 4;
        address targetAddress = 0xaD5db72456E417bb51d9e89425e6B2b9602dfc78;
        TargetNative receiverValue = TargetNative.wrap(0);
        Gas gasLimit = Gas.wrap(100_000);

        vm.recordLogs();
        uint64 sequence = wrcom_eth.sendPayloadToEvm{value: 100_000}(
            targetChain,
            targetAddress,
            abi.encode(msg.sender, 12345678),
            receiverValue,
            gasLimit
        );
        // Send ------------------------------------------------------------

        // off-chain ------------------------------------------------------------
        Vm.Log[] memory logs = vm.getRecordedLogs();
        bytes memory logData;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].emitter == address(wcom_eth)) {
                logData = logs[i].data;
            }
        }

        (
            uint64 s,
            uint32 nonce,
            bytes memory instruction,
            uint8 consistencyLevel
        ) = abi.decode(logData, (uint64, uint32, bytes, uint8));
        assertEq(sequence, s);
        assertEq(nonce, 0);

        (bytes32 h, bytes memory enc) = encodeVMCom(
            uint8(1),
            uint32(1720525446),
            nonce,
            wcom_eth.chainId(),
            bytes32(uint256(uint160(address(wcom_eth)))),
            sequence,
            consistencyLevel,
            instruction,
            uint32(0)
        );
        // off-chain ------------------------------------------------------------

        // Deliver ------------------------------------------------------------
        wrcom_bsc.deliver{value: 100000}(
            new bytes[](0),
            enc,
            payable(address(0)),
            hex""
        );

        logs = vm.getRecordedLogs();
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].emitter == address(wrcom_bsc)) {
                assertEq(logs[i].topics.length, 4);
                assertEq(
                    logs[i].topics[0],
                    keccak256(
                        abi.encodePacked(
                            "Delivery(address,uint16,uint64,bytes32,uint8,uint256,uint8,bytes,bytes)"
                        )
                    )
                );
                assertEq(
                    bytes32(uint256(uint160(targetAddress))),
                    logs[i].topics[1]
                );
                assertEq(
                    bytes32(uint256(uint16(w_eth.chainId()))),
                    logs[i].topics[2]
                );
                assertEq(bytes32(uint256(sequence)), logs[i].topics[3]);
                (bytes32 deliveryVaaHash, uint8 status, , , , ) = abi.decode(
                    logs[i].data,
                    (bytes32, uint8, uint256, uint8, bytes, bytes)
                );
                assertEq(deliveryVaaHash, h);
                assertEq(
                    status,
                    uint8(IWormholeRelayerDelivery.DeliveryStatus.SUCCESS)
                );
            }
        }
        // Deliver ------------------------------------------------------------
    }

    function test_send_cct_and_deliver_cct() public {
        uint256 gg;
        // Send on ETH ------------------------------------------------------------
        uint16 targetChain = 4;
        uint256 bridgeIndex = 0;
        uint256 gasLimit = 60_000;

        assertEq(cct_eth.balanceOf(alice), 200);
        assertEq(address(cct_eth.bridges(bridgeIndex)), address(wr_eth));

        vm.prank(alice);
        vm.recordLogs();
        gg = gasleft();
        cct_eth.sendTokens{value: gasLimit}(
            targetChain,
            bridgeIndex,
            100,
            Gas.wrap(gasLimit)
        );
        console.log("ETH: sendTokens's gasUsed = ", gg - gasleft());
        assertEq(cct_eth.balanceOf(alice), 100);
        // Send on ETH ------------------------------------------------------------

        // off-chain ------------------------------------------------------------
        Vm.Log[] memory logs = vm.getRecordedLogs();
        bytes memory logData;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].emitter == address(w_eth)) {
                logData = logs[i].data;
            } else if (
                logs[i].emitter == address(cct_eth) &&
                logs[i].topics[0] ==
                keccak256(
                    abi.encodePacked("TokenSent(address,uint16,uint256,uint64)")
                )
            ) {
                assertEq(logs[i].topics[1], bytes32(uint256(uint160(alice))));
                assertEq(logs[i].topics[2], bytes32(uint256(targetChain)));
                (uint256 _amount, uint64 _sequence) = abi.decode(
                    logs[i].data,
                    (uint256, uint64)
                );
                assertEq(_amount, 100);
                assertEq(_sequence, 0);
            }
        }

        (
            uint64 sequence,
            uint32 nonce,
            bytes memory instruction,
            uint8 consistencyLevel
        ) = abi.decode(logData, (uint64, uint32, bytes, uint8));
        assertEq(sequence, 0);
        assertEq(nonce, 0);

        (bytes32 h, ) = encodeLastPartWithHash(
            uint32(block.timestamp),
            nonce,
            w_eth.chainId(),
            bytes32(uint256(uint160(address(w_eth)))),
            sequence,
            consistencyLevel,
            instruction
        );
        Structs.Signature[] memory signatures = genMultiSigs(h);
        bytes memory enc = encodeVM(
            uint8(1),
            uint32(block.timestamp),
            nonce,
            w_eth.chainId(),
            bytes32(uint256(uint160(address(w_eth)))),
            sequence,
            consistencyLevel,
            instruction,
            uint32(0),
            signatures
        );
        // off-chain ------------------------------------------------------------

        // Deliver on BSC ------------------------------------------------------------
        assertEq(cct_bsc.balanceOf(alice), 0);
        gg = gasleft();
        wr_bsc.deliver{value: gasLimit}(
            new bytes[](0),
            enc,
            payable(address(0)),
            hex""
        );
        console.log("BSC: deliver's gasUsed = ", gg - gasleft());
        assertEq(cct_bsc.balanceOf(alice), 100);

        logs = vm.getRecordedLogs();
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].emitter == address(wr_bsc)) {
                assertEq(logs[i].topics.length, 4);
                assertEq(
                    logs[i].topics[0],
                    keccak256(
                        abi.encodePacked(
                            "Delivery(address,uint16,uint64,bytes32,uint8,uint256,uint8,bytes,bytes)"
                        )
                    )
                );
                assertEq(
                    bytes32(uint256(uint160(address(cct_bsc)))),
                    logs[i].topics[1]
                );
                assertEq(
                    bytes32(uint256(uint16(w_eth.chainId()))),
                    logs[i].topics[2]
                );
                assertEq(bytes32(uint256(sequence)), logs[i].topics[3]);
                (
                    bytes32 deliveryVaaHash,
                    uint8 status,
                    uint256 gasUsed,
                    ,
                    ,

                ) = abi.decode(
                        logs[i].data,
                        (bytes32, uint8, uint256, uint8, bytes, bytes)
                    );
                console.log("BSC: CCT's gasUsed = ", gasUsed);
                assertEq(deliveryVaaHash, h);
                assertEq(
                    status,
                    uint8(IWormholeRelayerDelivery.DeliveryStatus.SUCCESS)
                );
            } else if (
                logs[i].emitter == address(cct_bsc) &&
                logs[i].topics[0] ==
                keccak256(
                    abi.encodePacked("TokenReceived(address,uint16,uint256)")
                )
            ) {
                assertEq(bytes32(uint256(uint160(alice))), logs[i].topics[1]);
                assertEq(
                    bytes32(uint256(uint16(w_eth.chainId()))),
                    logs[i].topics[2]
                );
                uint256 _amount = abi.decode(logs[i].data, (uint256));
                assertEq(_amount, 100);
            }
        }
        // Deliver on BSC ------------------------------------------------------------

        // Send on BSC ------------------------------------------------------------
        targetChain = 2;
        gasLimit = 60_000;

        assertEq(cct_bsc.balanceOf(alice), 100);
        assertEq(address(cct_bsc.bridges(bridgeIndex)), address(wr_bsc));

        vm.prank(alice);
        vm.recordLogs();
        gg = gasleft();
        cct_bsc.sendTokens{value: gasLimit}(
            targetChain,
            bridgeIndex,
            50,
            Gas.wrap(gasLimit)
        );
        console.log("BSC: sendTokens's gasUsed = ", gg - gasleft());
        assertEq(cct_bsc.balanceOf(alice), 50);
        // Send on BSC ------------------------------------------------------------

        // off-chain ------------------------------------------------------------
        logs = vm.getRecordedLogs();
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].emitter == address(w_bsc)) {
                logData = logs[i].data;
            } else if (
                logs[i].emitter == address(cct_bsc) &&
                logs[i].topics[0] ==
                keccak256(
                    abi.encodePacked("TokenSent(address,uint16,uint256,uint64)")
                )
            ) {
                assertEq(logs[i].topics[1], bytes32(uint256(uint160(alice))));
                assertEq(logs[i].topics[2], bytes32(uint256(targetChain)));
                (uint256 _amount, uint64 _sequence) = abi.decode(
                    logs[i].data,
                    (uint256, uint64)
                );
                assertEq(_amount, 50);
                assertEq(_sequence, 0);
            }
        }
        (sequence, nonce, instruction, consistencyLevel) = abi.decode(
            logData,
            (uint64, uint32, bytes, uint8)
        );
        assertEq(sequence, 0);
        assertEq(nonce, 0);
        (h, ) = encodeLastPartWithHash(
            uint32(block.timestamp),
            nonce,
            w_bsc.chainId(),
            bytes32(uint256(uint160(address(w_bsc)))),
            sequence,
            consistencyLevel,
            instruction
        );
        signatures = genMultiSigs(h);
        enc = encodeVM(
            uint8(1),
            uint32(block.timestamp),
            nonce,
            w_bsc.chainId(),
            bytes32(uint256(uint160(address(w_bsc)))),
            sequence,
            consistencyLevel,
            instruction,
            uint32(0),
            signatures
        );
        // off-chain ------------------------------------------------------------

        // Deliver on ETH ------------------------------------------------------------
        assertEq(cct_eth.balanceOf(alice), 100);
        gg = gasleft();
        wr_eth.deliver{value: gasLimit}(
            new bytes[](0),
            enc,
            payable(address(0)),
            hex""
        );
        console.log("ETH: deliver's gasUsed = ", gg - gasleft());
        assertEq(cct_eth.balanceOf(alice), 150);

        logs = vm.getRecordedLogs();
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].emitter == address(wr_eth)) {
                assertEq(logs[i].topics.length, 4);
                assertEq(
                    logs[i].topics[0],
                    keccak256(
                        abi.encodePacked(
                            "Delivery(address,uint16,uint64,bytes32,uint8,uint256,uint8,bytes,bytes)"
                        )
                    )
                );
                assertEq(
                    bytes32(uint256(uint160(address(cct_eth)))),
                    logs[i].topics[1]
                );
                assertEq(
                    bytes32(uint256(uint16(w_bsc.chainId()))),
                    logs[i].topics[2]
                );
                assertEq(bytes32(uint256(sequence)), logs[i].topics[3]);
                (
                    bytes32 deliveryVaaHash,
                    uint8 status,
                    uint256 gasUsed,
                    ,
                    ,

                ) = abi.decode(
                        logs[i].data,
                        (bytes32, uint8, uint256, uint8, bytes, bytes)
                    );
                console.log("ETH: CCT's gasUsed = ", gasUsed);
                assertEq(deliveryVaaHash, h);
                assertEq(
                    status,
                    uint8(IWormholeRelayerDelivery.DeliveryStatus.SUCCESS)
                );
            } else if (
                logs[i].emitter == address(cct_eth) &&
                logs[i].topics[0] ==
                keccak256(
                    abi.encodePacked("TokenReceived(address,uint16,uint256)")
                )
            ) {
                assertEq(bytes32(uint256(uint160(alice))), logs[i].topics[1]);
                assertEq(
                    bytes32(uint256(uint16(w_bsc.chainId()))),
                    logs[i].topics[2]
                );
                uint256 _amount = abi.decode(logs[i].data, (uint256));
                assertEq(_amount, 50);
            }
        }
        // Deliver on ETH ------------------------------------------------------------
    }

    function test_send_cct_com_and_deliver_cct_com() public {
        uint256 gg;
        // Send on ETH ------------------------------------------------------------
        uint16 targetChain = 4;
        uint256 bridgeIndex = 1;
        uint256 gasLimit = 60_000;

        assertEq(cct_eth.balanceOf(alice), 200);
        assertEq(address(cct_eth.bridges(bridgeIndex)), address(wrcom_eth));

        vm.prank(alice);
        vm.recordLogs();
        gg = gasleft();
        cct_eth.sendTokens{value: gasLimit}(
            targetChain,
            bridgeIndex,
            100,
            Gas.wrap(gasLimit)
        );
        console.log("ETH: sendTokens's gasUsed = ", gg - gasleft());
        assertEq(cct_eth.balanceOf(alice), 100);
        // Send on ETH ------------------------------------------------------------

        // off-chain ------------------------------------------------------------
        Vm.Log[] memory logs = vm.getRecordedLogs();
        bytes memory logData;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].emitter == address(wcom_eth)) {
                logData = logs[i].data;
            } else if (
                logs[i].emitter == address(cct_eth) &&
                logs[i].topics[0] ==
                keccak256(
                    abi.encodePacked("TokenSent(address,uint16,uint256,uint64)")
                )
            ) {
                assertEq(logs[i].topics[1], bytes32(uint256(uint160(alice))));
                assertEq(logs[i].topics[2], bytes32(uint256(targetChain)));
                (uint256 _amount, uint64 _sequence) = abi.decode(
                    logs[i].data,
                    (uint256, uint64)
                );
                assertEq(_amount, 100);
                assertEq(_sequence, 0);
            }
        }

        (
            uint64 sequence,
            uint32 nonce,
            bytes memory instruction,
            uint8 consistencyLevel
        ) = abi.decode(logData, (uint64, uint32, bytes, uint8));
        assertEq(sequence, 0);
        assertEq(nonce, 0);

        (bytes32 h, bytes memory enc) = encodeVMCom(
            uint8(1),
            uint32(1720525446),
            nonce,
            wcom_eth.chainId(),
            bytes32(uint256(uint160(address(wcom_eth)))),
            sequence,
            consistencyLevel,
            instruction,
            uint32(0)
        );
        // off-chain ------------------------------------------------------------

        // Deliver on BSC ------------------------------------------------------------
        assertEq(cct_bsc.balanceOf(alice), 0);
        gg = gasleft();
        wrcom_bsc.deliver{value: gasLimit}(
            new bytes[](0),
            enc,
            payable(address(0)),
            hex""
        );
        console.log("BSC: deliver's gasUsed = ", gg - gasleft());
        assertEq(cct_bsc.balanceOf(alice), 100);

        logs = vm.getRecordedLogs();
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].emitter == address(wrcom_bsc)) {
                assertEq(logs[i].topics.length, 4);
                assertEq(
                    logs[i].topics[0],
                    keccak256(
                        abi.encodePacked(
                            "Delivery(address,uint16,uint64,bytes32,uint8,uint256,uint8,bytes,bytes)"
                        )
                    )
                );
                assertEq(
                    bytes32(uint256(uint160(address(cct_bsc)))),
                    logs[i].topics[1]
                );
                assertEq(
                    bytes32(uint256(uint16(wcom_eth.chainId()))),
                    logs[i].topics[2]
                );
                assertEq(bytes32(uint256(sequence)), logs[i].topics[3]);
                (
                    bytes32 deliveryVaaHash,
                    uint8 status,
                    uint256 gasUsed,
                    ,
                    ,

                ) = abi.decode(
                        logs[i].data,
                        (bytes32, uint8, uint256, uint8, bytes, bytes)
                    );
                console.log("BSC: CCT's gasUsed = ", gasUsed);
                assertEq(deliveryVaaHash, h);
                assertEq(
                    status,
                    uint8(IWormholeRelayerDelivery.DeliveryStatus.SUCCESS)
                );
            } else if (
                logs[i].emitter == address(cct_bsc) &&
                logs[i].topics[0] ==
                keccak256(
                    abi.encodePacked("TokenReceived(address,uint16,uint256)")
                )
            ) {
                assertEq(bytes32(uint256(uint160(alice))), logs[i].topics[1]);
                assertEq(
                    bytes32(uint256(uint16(wcom_eth.chainId()))),
                    logs[i].topics[2]
                );
                uint256 _amount = abi.decode(logs[i].data, (uint256));
                assertEq(_amount, 100);
            }
        }
        // Deliver on BSC ------------------------------------------------------------

        // Send on BSC ------------------------------------------------------------
        targetChain = 2;
        gasLimit = 60_000;

        assertEq(cct_bsc.balanceOf(alice), 100);
        assertEq(address(cct_bsc.bridges(bridgeIndex)), address(wrcom_bsc));

        vm.prank(alice);
        vm.recordLogs();
        gg = gasleft();
        cct_bsc.sendTokens{value: gasLimit}(
            targetChain,
            bridgeIndex,
            50,
            Gas.wrap(gasLimit)
        );
        console.log("BSC: sendTokens's gasUsed = ", gg - gasleft());
        assertEq(cct_bsc.balanceOf(alice), 50);
        // Send on BSC ------------------------------------------------------------

        // off-chain ------------------------------------------------------------
        logs = vm.getRecordedLogs();
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].emitter == address(wcom_bsc)) {
                logData = logs[i].data;
            } else if (
                logs[i].emitter == address(cct_bsc) &&
                logs[i].topics[0] ==
                keccak256(
                    abi.encodePacked("TokenSent(address,uint16,uint256,uint64)")
                )
            ) {
                assertEq(logs[i].topics[1], bytes32(uint256(uint160(alice))));
                assertEq(logs[i].topics[2], bytes32(uint256(targetChain)));
                (uint256 _amount, uint64 _sequence) = abi.decode(
                    logs[i].data,
                    (uint256, uint64)
                );
                assertEq(_amount, 50);
                assertEq(_sequence, 0);
            }
        }
        (sequence, nonce, instruction, consistencyLevel) = abi.decode(
            logData,
            (uint64, uint32, bytes, uint8)
        );
        assertEq(sequence, 0);
        assertEq(nonce, 0);
        (h, enc) = encodeVMCom(
            uint8(1),
            uint32(1720525446),
            nonce,
            wcom_bsc.chainId(),
            bytes32(uint256(uint160(address(wcom_bsc)))),
            sequence,
            consistencyLevel,
            instruction,
            uint32(0)
        );
        // off-chain ------------------------------------------------------------

        // Deliver on ETH ------------------------------------------------------------
        assertEq(cct_eth.balanceOf(alice), 100);
        gg = gasleft();
        wrcom_eth.deliver{value: gasLimit}(
            new bytes[](0),
            enc,
            payable(address(0)),
            hex""
        );
        console.log("ETH: deliver's gasUsed = ", gg - gasleft());
        assertEq(cct_eth.balanceOf(alice), 150);

        logs = vm.getRecordedLogs();
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].emitter == address(wrcom_eth)) {
                assertEq(logs[i].topics.length, 4);
                assertEq(
                    logs[i].topics[0],
                    keccak256(
                        abi.encodePacked(
                            "Delivery(address,uint16,uint64,bytes32,uint8,uint256,uint8,bytes,bytes)"
                        )
                    )
                );
                assertEq(
                    bytes32(uint256(uint160(address(cct_eth)))),
                    logs[i].topics[1]
                );
                assertEq(
                    bytes32(uint256(uint16(wcom_bsc.chainId()))),
                    logs[i].topics[2]
                );
                assertEq(bytes32(uint256(sequence)), logs[i].topics[3]);
                (
                    bytes32 deliveryVaaHash,
                    uint8 status,
                    uint256 gasUsed,
                    ,
                    ,

                ) = abi.decode(
                        logs[i].data,
                        (bytes32, uint8, uint256, uint8, bytes, bytes)
                    );
                console.log("ETH: CCT's gasUsed = ", gasUsed);
                assertEq(deliveryVaaHash, h);
                assertEq(
                    status,
                    uint8(IWormholeRelayerDelivery.DeliveryStatus.SUCCESS)
                );
            } else if (
                logs[i].emitter == address(cct_eth) &&
                logs[i].topics[0] ==
                keccak256(
                    abi.encodePacked("TokenReceived(address,uint16,uint256)")
                )
            ) {
                assertEq(bytes32(uint256(uint160(alice))), logs[i].topics[1]);
                assertEq(
                    bytes32(uint256(uint16(wcom_bsc.chainId()))),
                    logs[i].topics[2]
                );
                uint256 _amount = abi.decode(logs[i].data, (uint256));
                assertEq(_amount, 50);
            }
        }
        // Deliver on ETH ------------------------------------------------------------
    }
}
