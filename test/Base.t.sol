// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console, Vm} from "forge-std/Test.sol";
import "../src/Types.sol";
import {WormholeRelayer} from "../src/WormholeRelayer.sol";
import {Wormhole} from "../src/Wormhole.sol";
import {DeliveryProvider} from "../src/DeliveryProvider.sol";

contract WHTest is Test {
    WormholeRelayer public wr_eth;
    Wormhole public w_eth;
    DeliveryProvider public dp_eth;

    WormholeRelayer public wr_bsc;
    Wormhole public w_bsc;
    DeliveryProvider public dp_bsc;

    function setUp() public {
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

    function test_1() public view {
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

    function test_2() public {
        uint64 sequence;

        // ETH ------------------------------------------------------------
        uint16 targetChain = 4;
        address targetAddress = 0xaD5db72456E417bb51d9e89425e6B2b9602dfc78;
        bytes memory payload = abi.encode(msg.sender, 100);
        TargetNative receiverValue = TargetNative.wrap(0);
        Gas gasLimit = Gas.wrap(100_000);

        uint256 g = gasleft();
        sequence = wr_eth.sendPayloadToEvm{value: 100_000}(
            targetChain,
            targetAddress,
            payload,
            receiverValue,
            gasLimit
        );
        console.log("ETH-1. GAS USED = ", g - gasleft());
        assertEq(sequence, 0);
        g = gasleft();
        sequence = wr_eth.sendPayloadToEvm{value: 100_000}(
            targetChain,
            targetAddress,
            payload,
            receiverValue,
            gasLimit
        );
        console.log("ETH-2. GAS USED = ", g - gasleft());
        assertEq(sequence, 1);
        g = gasleft();
        sequence = wr_eth.sendPayloadToEvm{value: 100_000}(
            targetChain,
            targetAddress,
            payload,
            receiverValue,
            gasLimit
        );
        console.log("ETH-3. GAS USED = ", g - gasleft());
        assertEq(sequence, 2);

        // BSC ------------------------------------------------------------
        targetChain = 2;
        targetAddress = 0x7c8F69947FD70615170295d806e0fC99FfcA7b1E;
        payload = abi.encode(msg.sender, 100);
        receiverValue = TargetNative.wrap(0);
        gasLimit = Gas.wrap(100_000);

        g = gasleft();
        sequence = wr_bsc.sendPayloadToEvm{value: 100_000}(
            targetChain,
            targetAddress,
            payload,
            receiverValue,
            gasLimit
        );
        console.log("BSC-1. GAS USED = ", g - gasleft());
        assertEq(sequence, 0);
        g = gasleft();
        sequence = wr_bsc.sendPayloadToEvm{value: 100_000}(
            targetChain,
            targetAddress,
            payload,
            receiverValue,
            gasLimit
        );
        console.log("BSC-2. GAS USED = ", g - gasleft());
        assertEq(sequence, 1);
        g = gasleft();
        sequence = wr_bsc.sendPayloadToEvm{value: 100_000}(
            targetChain,
            targetAddress,
            payload,
            receiverValue,
            gasLimit
        );
        console.log("BSC-3. GAS USED = ", g - gasleft());
        assertEq(sequence, 2);
    }

    function test_3() public {
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
}
