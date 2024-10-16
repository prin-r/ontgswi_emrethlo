// // SPDX-License-Identifier: MIT
// pragma solidity ^0.8.20;

// // OpenZeppelin ERC20 implementation
// import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

// // Type definitions (adjust according to Wormhole's SDK)
// type TargetNative is uint256;
// type Gas is uint256;

// // IWormholeRelayer interface
// interface IWormholeRelayer {
//     function sendPayloadToEvm(
//         uint16 targetChain,
//         bytes32 targetAddress,
//         bytes memory payload,
//         TargetNative receiverValue,
//         Gas gasLimit
//     ) external payable returns (uint64 sequence);

//     function quoteEVMDeliveryPrice(
//         uint16 targetChain,
//         TargetNative receiverValue,
//         Gas gasLimit
//     )
//         external
//         view
//         returns (
//             uint256 nativePriceQuote,
//             uint256 targetChainRefundPerGasUnused
//         );
// }

// // IWormholeReceiver interface
// interface IWormholeReceiver {
//     function receiveWormholeMessages(
//         bytes memory payload,
//         bytes[] memory additionalVaas,
//         bytes32 sourceAddress,
//         uint16 sourceChain,
//         bytes32 deliveryHash
//     ) external payable;
// }

// contract CrossChainToken is ERC20, IWormholeReceiver {
//     IWormholeRelayer public wormholeRelayer;
//     mapping(uint16 => bytes32) public registeredContracts;

//     event TokenSent(
//         address indexed sender,
//         uint16 indexed targetChain,
//         uint256 amount,
//         uint64 sequence
//     );
//     event TokenReceived(
//         address indexed recipient,
//         uint16 indexed sourceChain,
//         uint256 amount
//     );

//     constructor(
//         string memory name_,
//         string memory symbol_,
//         address wormholeRelayerAddress_
//     ) ERC20(name_, symbol_) {
//         wormholeRelayer = IWormholeRelayer(wormholeRelayerAddress_);
//     }

//     function registerContract(uint16 chainId, bytes32 contractAddress)
//         external
//     {
//         registeredContracts[chainId] = contractAddress;
//     }

//     function sendTokens(
//         uint16 targetChain,
//         uint256 amount,
//         Gas gasLimit
//     ) external payable {
//         bytes32 targetContract = registeredContracts[targetChain];
//         require(targetContract != bytes32(0), "Target chain not registered");
//         require(amount <= balanceOf(msg.sender), "Insufficient balance");

//         // Burn tokens from sender
//         _burn(msg.sender, amount);

//         // Prepare payload
//         bytes memory payload = abi.encode(msg.sender, amount);

//         // This function is unrelated to the native token
//         TargetNative receiverValue = TargetNative.wrap(0);

//         // Estimate fee
//         (uint256 estimatedFee, ) = wormholeRelayer.quoteEVMDeliveryPrice(
//             targetChain,
//             receiverValue,
//             gasLimit
//         );
//         require(msg.value >= estimatedFee, "Insufficient fee");

//         // Send payload via Wormhole
//         uint64 sequence = wormholeRelayer.sendPayloadToEvm{value: msg.value}(
//             targetChain,
//             targetContract,
//             payload,
//             receiverValue,
//             gasLimit
//         );

//         emit TokenSent(msg.sender, targetChain, amount, sequence);
//     }

//     function receiveWormholeMessages(
//         bytes memory payload,
//         bytes[] memory,
//         bytes32,
//         uint16 sourceChain,
//         bytes32
//     ) external payable override {
//         require(msg.sender == address(wormholeRelayer), "Unauthorized caller");

//         (address recipient, uint256 amount) = abi.decode(
//             payload,
//             (address, uint256)
//         );

//         _mint(recipient, amount);

//         emit TokenReceived(recipient, sourceChain, amount);
//     }
// }
