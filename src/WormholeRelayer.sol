// SPDX-License-Identifier: MIT

pragma solidity ^0.8.20;

import "./Types.sol";

/**
 * @dev Library for reading and writing primitive types to specific storage slots.
 *
 * Storage slots are often used to avoid storage conflict when dealing with upgradeable contracts.
 * This library helps with reading and writing to such slots without the need for inline assembly.
 *
 * The functions in this library return Slot structs that contain a `value` member that can be used to read or write.
 *
 * Example usage to set ERC1967 implementation slot:
 * ```
 * contract ERC1967 {
 *     bytes32 internal constant _IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
 *
 *     function _getImplementation() internal view returns (address) {
 *         return StorageSlot.getAddressSlot(_IMPLEMENTATION_SLOT).value;
 *     }
 *
 *     function _setImplementation(address newImplementation) internal {
 *         require(Address.isContract(newImplementation), "ERC1967: new implementation is not a contract");
 *         StorageSlot.getAddressSlot(_IMPLEMENTATION_SLOT).value = newImplementation;
 *     }
 * }
 * ```
 *
 * _Available since v4.1 for `address`, `bool`, `bytes32`, and `uint256`._
 */
library StorageSlot {
    struct AddressSlot {
        address value;
    }

    struct BooleanSlot {
        bool value;
    }

    struct Bytes32Slot {
        bytes32 value;
    }

    struct Uint256Slot {
        uint256 value;
    }

    /**
     * @dev Returns an `AddressSlot` with member `value` located at `slot`.
     */
    function getAddressSlot(bytes32 slot) internal pure returns (AddressSlot storage r) {
        assembly {
            r.slot := slot
        }
    }

    /**
     * @dev Returns an `BooleanSlot` with member `value` located at `slot`.
     */
    function getBooleanSlot(bytes32 slot) internal pure returns (BooleanSlot storage r) {
        assembly {
            r.slot := slot
        }
    }

    /**
     * @dev Returns an `Bytes32Slot` with member `value` located at `slot`.
     */
    function getBytes32Slot(bytes32 slot) internal pure returns (Bytes32Slot storage r) {
        assembly {
            r.slot := slot
        }
    }

    /**
     * @dev Returns an `Uint256Slot` with member `value` located at `slot`.
     */
    function getUint256Slot(bytes32 slot) internal pure returns (Uint256Slot storage r) {
        assembly {
            r.slot := slot
        }
    }
}

/**
 * @dev Collection of functions related to the address type
 */
library Address {
    /**
     * @dev Returns true if `account` is a contract.
     *
     * [IMPORTANT]
     * ====
     * It is unsafe to assume that an address for which this function returns
     * false is an externally-owned account (EOA) and not a contract.
     *
     * Among others, `isContract` will return false for the following
     * types of addresses:
     *
     *  - an externally-owned account
     *  - a contract in construction
     *  - an address where a contract will be created
     *  - an address where a contract lived, but was destroyed
     * ====
     */
    function isContract(address account) internal view returns (bool) {
        // This method relies on extcodesize, which returns 0 for contracts in
        // construction, since the code is only stored at the end of the
        // constructor execution.

        uint256 size;
        assembly {
            size := extcodesize(account)
        }
        return size > 0;
    }

    /**
     * @dev Replacement for Solidity's `transfer`: sends `amount` wei to
     * `recipient`, forwarding all available gas and reverting on errors.
     *
     * https://eips.ethereum.org/EIPS/eip-1884[EIP1884] increases the gas cost
     * of certain opcodes, possibly making contracts go over the 2300 gas limit
     * imposed by `transfer`, making them unable to receive funds via
     * `transfer`. {sendValue} removes this limitation.
     *
     * https://diligence.consensys.net/posts/2019/09/stop-using-soliditys-transfer-now/[Learn more].
     *
     * IMPORTANT: because control is transferred to `recipient`, care must be
     * taken to not create reentrancy vulnerabilities. Consider using
     * {ReentrancyGuard} or the
     * https://solidity.readthedocs.io/en/v0.5.11/security-considerations.html#use-the-checks-effects-interactions-pattern[checks-effects-interactions pattern].
     */
    function sendValue(address payable recipient, uint256 amount) internal {
        require(address(this).balance >= amount, "Address: insufficient balance");

        (bool success, ) = recipient.call{value: amount}("");
        require(success, "Address: unable to send value, recipient may have reverted");
    }

    /**
     * @dev Performs a Solidity function call using a low level `call`. A
     * plain `call` is an unsafe replacement for a function call: use this
     * function instead.
     *
     * If `target` reverts with a revert reason, it is bubbled up by this
     * function (like regular Solidity function calls).
     *
     * Returns the raw returned data. To convert to the expected return value,
     * use https://solidity.readthedocs.io/en/latest/units-and-global-variables.html?highlight=abi.decode#abi-encoding-and-decoding-functions[`abi.decode`].
     *
     * Requirements:
     *
     * - `target` must be a contract.
     * - calling `target` with `data` must not revert.
     *
     * _Available since v3.1._
     */
    function functionCall(address target, bytes memory data) internal returns (bytes memory) {
        return functionCall(target, data, "Address: low-level call failed");
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`], but with
     * `errorMessage` as a fallback revert reason when `target` reverts.
     *
     * _Available since v3.1._
     */
    function functionCall(
        address target,
        bytes memory data,
        string memory errorMessage
    ) internal returns (bytes memory) {
        return functionCallWithValue(target, data, 0, errorMessage);
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`],
     * but also transferring `value` wei to `target`.
     *
     * Requirements:
     *
     * - the calling contract must have an ETH balance of at least `value`.
     * - the called Solidity function must be `payable`.
     *
     * _Available since v3.1._
     */
    function functionCallWithValue(
        address target,
        bytes memory data,
        uint256 value
    ) internal returns (bytes memory) {
        return functionCallWithValue(target, data, value, "Address: low-level call with value failed");
    }

    /**
     * @dev Same as {xref-Address-functionCallWithValue-address-bytes-uint256-}[`functionCallWithValue`], but
     * with `errorMessage` as a fallback revert reason when `target` reverts.
     *
     * _Available since v3.1._
     */
    function functionCallWithValue(
        address target,
        bytes memory data,
        uint256 value,
        string memory errorMessage
    ) internal returns (bytes memory) {
        require(address(this).balance >= value, "Address: insufficient balance for call");
        require(isContract(target), "Address: call to non-contract");

        (bool success, bytes memory returndata) = target.call{value: value}(data);
        return verifyCallResult(success, returndata, errorMessage);
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`],
     * but performing a static call.
     *
     * _Available since v3.3._
     */
    function functionStaticCall(address target, bytes memory data) internal view returns (bytes memory) {
        return functionStaticCall(target, data, "Address: low-level static call failed");
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-string-}[`functionCall`],
     * but performing a static call.
     *
     * _Available since v3.3._
     */
    function functionStaticCall(
        address target,
        bytes memory data,
        string memory errorMessage
    ) internal view returns (bytes memory) {
        require(isContract(target), "Address: static call to non-contract");

        (bool success, bytes memory returndata) = target.staticcall(data);
        return verifyCallResult(success, returndata, errorMessage);
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`],
     * but performing a delegate call.
     *
     * _Available since v3.4._
     */
    function functionDelegateCall(address target, bytes memory data) internal returns (bytes memory) {
        return functionDelegateCall(target, data, "Address: low-level delegate call failed");
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-string-}[`functionCall`],
     * but performing a delegate call.
     *
     * _Available since v3.4._
     */
    function functionDelegateCall(
        address target,
        bytes memory data,
        string memory errorMessage
    ) internal returns (bytes memory) {
        require(isContract(target), "Address: delegate call to non-contract");

        (bool success, bytes memory returndata) = target.delegatecall(data);
        return verifyCallResult(success, returndata, errorMessage);
    }

    /**
     * @dev Tool to verifies that a low level call was successful, and revert if it wasn't, either by bubbling the
     * revert reason using the provided one.
     *
     * _Available since v4.3._
     */
    function verifyCallResult(
        bool success,
        bytes memory returndata,
        string memory errorMessage
    ) internal pure returns (bytes memory) {
        if (success) {
            return returndata;
        } else {
            // Look for revert reason and bubble it up if present
            if (returndata.length > 0) {
                // The easiest way to bubble the revert reason is using memory via assembly

                assembly {
                    let returndata_size := mload(returndata)
                    revert(add(32, returndata), returndata_size)
                }
            } else {
                revert(errorMessage);
            }
        }
    }
}

/**
 * @dev This is the interface that {BeaconProxy} expects of its beacon.
 */
interface IBeacon {
    /**
     * @dev Must return an address that can be used as a delegate call target.
     *
     * {BeaconProxy} will check that this address is a contract.
     */
    function implementation() external view returns (address);
}

/**
 * @notice Interface for a contract which can receive Wormhole messages.
 */
interface IWormholeReceiver {
    /**
     * @notice When a `send` is performed with this contract as the target, this function will be
     *     invoked by the WormholeRelayer contract
     *
     * NOTE: This function should be restricted such that only the Wormhole Relayer contract can call it.
     *
     * We also recommend that this function:
     *   - Stores all received `deliveryHash`s in a mapping `(bytes32 => bool)`, and
     *       on every call, checks that deliveryHash has not already been stored in the
     *       map (This is to prevent other users maliciously trying to relay the same message)
     *   - Checks that `sourceChain` and `sourceAddress` are indeed who
     *       you expect to have requested the calling of `send` on the source chain
     *
     * The invocation of this function corresponding to the `send` request will have msg.value equal
     *   to the receiverValue specified in the send request.
     *
     * If the invocation of this function reverts or exceeds the gas limit 
     *   specified by the send requester, this delivery will result in a `ReceiverFailure`.
     *
     * @param payload - an arbitrary message which was included in the delivery by the
     *     requester.
     * @param additionalVaas - Additional VAAs which were requested to be included in this delivery.
     *   They are guaranteed to all be included and in the same order as was specified in the
     *     delivery request.
     * @param sourceAddress - the (wormhole format) address on the sending chain which requested
     *     this delivery.
     * @param sourceChain - the wormhole chain ID where this delivery was requested.
     * @param deliveryHash - the VAA hash of the deliveryVAA.
     *
     * NOTE: These signedVaas are NOT verified by the Wormhole core contract prior to being provided
     *     to this call. Always make sure `parseAndVerify()` is called on the Wormhole core contract
     *     before trusting the content of a raw VAA, otherwise the VAA may be invalid or malicious.
     */
    function receiveWormholeMessages(
        bytes memory payload,
        bytes[] memory additionalVaas,
        bytes32 sourceAddress,
        uint16 sourceChain,
        bytes32 deliveryHash
    ) external payable;
}

library BytesParsing {
  uint256 private constant freeMemoryPtr = 0x40;
  uint256 private constant wordSize = 32;

  error OutOfBounds(uint256 offset, uint256 length);

  function checkBound(uint offset, uint length) internal pure {
    if (offset > length)
      revert OutOfBounds(offset, length);
  }

  function sliceUnchecked(
    bytes memory encoded,
    uint offset,
    uint length
  ) internal pure returns (bytes memory ret, uint nextOffset) {
    //bail early for degenerate case
    if (length == 0)
      return (new bytes(0), offset);

    assembly ("memory-safe") {
      nextOffset := add(offset, length)
      ret := mload(freeMemoryPtr)

      //Explanation on how we copy data here:
      //  The bytes type has the following layout in memory:
      //    [length: 32 bytes, data: length bytes]
      //  So if we allocate `bytes memory foo = new bytes(1);` then `foo` will be a pointer to 33
      //    bytes where the first 32 bytes contain the length and the last byte is the actual data.
      //  Since mload always loads 32 bytes of memory at once, we use our shift variable to align
      //    our reads so that our last read lines up exactly with the last 32 bytes of `encoded`.
      //  However this also means that if the length of `encoded` is not a multiple of 32 bytes, our
      //    first read will necessarily partly contain bytes from `encoded`'s 32 length bytes that
      //    will be written into the length part of our `ret` slice.
      //  We remedy this issue by writing the length of our `ret` slice at the end, thus
      //    overwritting those garbage bytes.
      let shift := and(length, 31) //equivalent to `mod(length, 32)` but 2 gas cheaper
      if iszero(shift) {
        shift := wordSize
      }

      let dest := add(ret, shift)
      let end := add(dest, length)
      for {
        let src := add(add(encoded, shift), offset)
      } lt(dest, end) {
        src := add(src, wordSize)
        dest := add(dest, wordSize)
      } {
        mstore(dest, mload(src))
      }

      mstore(ret, length)
      //When compiling with --via-ir then normally allocated memory (i.e. via new) will have 32 byte
      //  memory alignment and so we enforce the same memory alignment here.
      mstore(freeMemoryPtr, and(add(dest, 31), not(31)))
    }
  }

  function slice(
    bytes memory encoded,
    uint offset,
    uint length
  ) internal pure returns (bytes memory ret, uint nextOffset) {
    (ret, nextOffset) = sliceUnchecked(encoded, offset, length);
    checkBound(nextOffset, encoded.length);
  }

  function asAddressUnchecked(
    bytes memory encoded,
    uint offset
  ) internal pure returns (address, uint) {
    (uint160 ret, uint nextOffset) = asUint160(encoded, offset);
    return (address(ret), nextOffset);
  }

  function asAddress(
    bytes memory encoded,
    uint offset
  ) internal pure returns (address ret, uint nextOffset) {
    (ret, nextOffset) = asAddressUnchecked(encoded, offset);
    checkBound(nextOffset, encoded.length);
  }

  function asBoolUnckecked(
    bytes memory encoded,
    uint offset
  ) internal pure returns (bool, uint) {
    (uint8 ret, uint nextOffset) = asUint8(encoded, offset);
    return (ret != 0, nextOffset);
  }

  function asBool(
    bytes memory encoded,
    uint offset
  ) internal pure returns (bool ret, uint nextOffset) {
    (ret, nextOffset) = asBoolUnckecked(encoded, offset);
    checkBound(nextOffset, encoded.length);
  }

/* -------------------------------------------------------------------------------------------------
Remaining library code below was auto-generated by via the following js/node code:

for (let bytes = 1; bytes <= 32; ++bytes) {
  const bits = bytes*8;
  console.log(
`function asUint${bits}Unchecked(
  bytes memory encoded,
  uint offset
) internal pure returns (uint${bits} ret, uint nextOffset) {
  assembly ("memory-safe") {
    nextOffset := add(offset, ${bytes})
    ret := mload(add(encoded, nextOffset))
  }
  return (ret, nextOffset);
}

function asUint${bits}(
  bytes memory encoded,
  uint offset
) internal pure returns (uint${bits} ret, uint nextOffset) {
  (ret, nextOffset) = asUint${bits}Unchecked(encoded, offset);
  checkBound(nextOffset, encoded.length);
}

function asBytes${bytes}Unchecked(
  bytes memory encoded,
  uint offset
) internal pure returns (bytes${bytes}, uint) {
  (uint${bits} ret, uint nextOffset) = asUint${bits}Unchecked(encoded, offset);
  return (bytes${bytes}(ret), nextOffset);
}

function asBytes${bytes}(
  bytes memory encoded,
  uint offset
) internal pure returns (bytes${bytes}, uint) {
  (uint${bits} ret, uint nextOffset) = asUint${bits}(encoded, offset);
  return (bytes${bytes}(ret), nextOffset);
}
`
  );
}
------------------------------------------------------------------------------------------------- */

  function asUint8Unchecked(
    bytes memory encoded,
    uint offset
  ) internal pure returns (uint8 ret, uint nextOffset) {
    assembly ("memory-safe") {
      nextOffset := add(offset, 1)
      ret := mload(add(encoded, nextOffset))
    }
    return (ret, nextOffset);
  }

  function asUint8(
    bytes memory encoded,
    uint offset
  ) internal pure returns (uint8 ret, uint nextOffset) {
    (ret, nextOffset) = asUint8Unchecked(encoded, offset);
    checkBound(nextOffset, encoded.length);
  }

  function asBytes1Unchecked(
    bytes memory encoded,
    uint offset
  ) internal pure returns (bytes1, uint) {
    (uint8 ret, uint nextOffset) = asUint8Unchecked(encoded, offset);
    return (bytes1(ret), nextOffset);
  }

  function asBytes1(
    bytes memory encoded,
    uint offset
  ) internal pure returns (bytes1, uint) {
    (uint8 ret, uint nextOffset) = asUint8(encoded, offset);
    return (bytes1(ret), nextOffset);
  }

  function asUint16Unchecked(
    bytes memory encoded,
    uint offset
  ) internal pure returns (uint16 ret, uint nextOffset) {
    assembly ("memory-safe") {
      nextOffset := add(offset, 2)
      ret := mload(add(encoded, nextOffset))
    }
    return (ret, nextOffset);
  }

  function asUint16(
    bytes memory encoded,
    uint offset
  ) internal pure returns (uint16 ret, uint nextOffset) {
    (ret, nextOffset) = asUint16Unchecked(encoded, offset);
    checkBound(nextOffset, encoded.length);
  }

  function asBytes2Unchecked(
    bytes memory encoded,
    uint offset
  ) internal pure returns (bytes2, uint) {
    (uint16 ret, uint nextOffset) = asUint16Unchecked(encoded, offset);
    return (bytes2(ret), nextOffset);
  }

  function asBytes2(
    bytes memory encoded,
    uint offset
  ) internal pure returns (bytes2, uint) {
    (uint16 ret, uint nextOffset) = asUint16(encoded, offset);
    return (bytes2(ret), nextOffset);
  }

  function asUint24Unchecked(
    bytes memory encoded,
    uint offset
  ) internal pure returns (uint24 ret, uint nextOffset) {
    assembly ("memory-safe") {
      nextOffset := add(offset, 3)
      ret := mload(add(encoded, nextOffset))
    }
    return (ret, nextOffset);
  }

  function asUint24(
    bytes memory encoded,
    uint offset
  ) internal pure returns (uint24 ret, uint nextOffset) {
    (ret, nextOffset) = asUint24Unchecked(encoded, offset);
    checkBound(nextOffset, encoded.length);
  }

  function asBytes3Unchecked(
    bytes memory encoded,
    uint offset
  ) internal pure returns (bytes3, uint) {
    (uint24 ret, uint nextOffset) = asUint24Unchecked(encoded, offset);
    return (bytes3(ret), nextOffset);
  }

  function asBytes3(
    bytes memory encoded,
    uint offset
  ) internal pure returns (bytes3, uint) {
    (uint24 ret, uint nextOffset) = asUint24(encoded, offset);
    return (bytes3(ret), nextOffset);
  }

  function asUint32Unchecked(
    bytes memory encoded,
    uint offset
  ) internal pure returns (uint32 ret, uint nextOffset) {
    assembly ("memory-safe") {
      nextOffset := add(offset, 4)
      ret := mload(add(encoded, nextOffset))
    }
    return (ret, nextOffset);
  }

  function asUint32(
    bytes memory encoded,
    uint offset
  ) internal pure returns (uint32 ret, uint nextOffset) {
    (ret, nextOffset) = asUint32Unchecked(encoded, offset);
    checkBound(nextOffset, encoded.length);
  }

  function asBytes4Unchecked(
    bytes memory encoded,
    uint offset
  ) internal pure returns (bytes4, uint) {
    (uint32 ret, uint nextOffset) = asUint32Unchecked(encoded, offset);
    return (bytes4(ret), nextOffset);
  }

  function asBytes4(
    bytes memory encoded,
    uint offset
  ) internal pure returns (bytes4, uint) {
    (uint32 ret, uint nextOffset) = asUint32(encoded, offset);
    return (bytes4(ret), nextOffset);
  }

  function asUint40Unchecked(
    bytes memory encoded,
    uint offset
  ) internal pure returns (uint40 ret, uint nextOffset) {
    assembly ("memory-safe") {
      nextOffset := add(offset, 5)
      ret := mload(add(encoded, nextOffset))
    }
    return (ret, nextOffset);
  }

  function asUint40(
    bytes memory encoded,
    uint offset
  ) internal pure returns (uint40 ret, uint nextOffset) {
    (ret, nextOffset) = asUint40Unchecked(encoded, offset);
    checkBound(nextOffset, encoded.length);
  }

  function asBytes5Unchecked(
    bytes memory encoded,
    uint offset
  ) internal pure returns (bytes5, uint) {
    (uint40 ret, uint nextOffset) = asUint40Unchecked(encoded, offset);
    return (bytes5(ret), nextOffset);
  }

  function asBytes5(
    bytes memory encoded,
    uint offset
  ) internal pure returns (bytes5, uint) {
    (uint40 ret, uint nextOffset) = asUint40(encoded, offset);
    return (bytes5(ret), nextOffset);
  }

  function asUint48Unchecked(
    bytes memory encoded,
    uint offset
  ) internal pure returns (uint48 ret, uint nextOffset) {
    assembly ("memory-safe") {
      nextOffset := add(offset, 6)
      ret := mload(add(encoded, nextOffset))
    }
    return (ret, nextOffset);
  }

  function asUint48(
    bytes memory encoded,
    uint offset
  ) internal pure returns (uint48 ret, uint nextOffset) {
    (ret, nextOffset) = asUint48Unchecked(encoded, offset);
    checkBound(nextOffset, encoded.length);
  }

  function asBytes6Unchecked(
    bytes memory encoded,
    uint offset
  ) internal pure returns (bytes6, uint) {
    (uint48 ret, uint nextOffset) = asUint48Unchecked(encoded, offset);
    return (bytes6(ret), nextOffset);
  }

  function asBytes6(
    bytes memory encoded,
    uint offset
  ) internal pure returns (bytes6, uint) {
    (uint48 ret, uint nextOffset) = asUint48(encoded, offset);
    return (bytes6(ret), nextOffset);
  }

  function asUint56Unchecked(
    bytes memory encoded,
    uint offset
  ) internal pure returns (uint56 ret, uint nextOffset) {
    assembly ("memory-safe") {
      nextOffset := add(offset, 7)
      ret := mload(add(encoded, nextOffset))
    }
    return (ret, nextOffset);
  }

  function asUint56(
    bytes memory encoded,
    uint offset
  ) internal pure returns (uint56 ret, uint nextOffset) {
    (ret, nextOffset) = asUint56Unchecked(encoded, offset);
    checkBound(nextOffset, encoded.length);
  }

  function asBytes7Unchecked(
    bytes memory encoded,
    uint offset
  ) internal pure returns (bytes7, uint) {
    (uint56 ret, uint nextOffset) = asUint56Unchecked(encoded, offset);
    return (bytes7(ret), nextOffset);
  }

  function asBytes7(
    bytes memory encoded,
    uint offset
  ) internal pure returns (bytes7, uint) {
    (uint56 ret, uint nextOffset) = asUint56(encoded, offset);
    return (bytes7(ret), nextOffset);
  }

  function asUint64Unchecked(
    bytes memory encoded,
    uint offset
  ) internal pure returns (uint64 ret, uint nextOffset) {
    assembly ("memory-safe") {
      nextOffset := add(offset, 8)
      ret := mload(add(encoded, nextOffset))
    }
    return (ret, nextOffset);
  }

  function asUint64(
    bytes memory encoded,
    uint offset
  ) internal pure returns (uint64 ret, uint nextOffset) {
    (ret, nextOffset) = asUint64Unchecked(encoded, offset);
    checkBound(nextOffset, encoded.length);
  }

  function asBytes8Unchecked(
    bytes memory encoded,
    uint offset
  ) internal pure returns (bytes8, uint) {
    (uint64 ret, uint nextOffset) = asUint64Unchecked(encoded, offset);
    return (bytes8(ret), nextOffset);
  }

  function asBytes8(
    bytes memory encoded,
    uint offset
  ) internal pure returns (bytes8, uint) {
    (uint64 ret, uint nextOffset) = asUint64(encoded, offset);
    return (bytes8(ret), nextOffset);
  }

  function asUint72Unchecked(
    bytes memory encoded,
    uint offset
  ) internal pure returns (uint72 ret, uint nextOffset) {
    assembly ("memory-safe") {
      nextOffset := add(offset, 9)
      ret := mload(add(encoded, nextOffset))
    }
    return (ret, nextOffset);
  }

  function asUint72(
    bytes memory encoded,
    uint offset
  ) internal pure returns (uint72 ret, uint nextOffset) {
    (ret, nextOffset) = asUint72Unchecked(encoded, offset);
    checkBound(nextOffset, encoded.length);
  }

  function asBytes9Unchecked(
    bytes memory encoded,
    uint offset
  ) internal pure returns (bytes9, uint) {
    (uint72 ret, uint nextOffset) = asUint72Unchecked(encoded, offset);
    return (bytes9(ret), nextOffset);
  }

  function asBytes9(
    bytes memory encoded,
    uint offset
  ) internal pure returns (bytes9, uint) {
    (uint72 ret, uint nextOffset) = asUint72(encoded, offset);
    return (bytes9(ret), nextOffset);
  }

  function asUint80Unchecked(
    bytes memory encoded,
    uint offset
  ) internal pure returns (uint80 ret, uint nextOffset) {
    assembly ("memory-safe") {
      nextOffset := add(offset, 10)
      ret := mload(add(encoded, nextOffset))
    }
    return (ret, nextOffset);
  }

  function asUint80(
    bytes memory encoded,
    uint offset
  ) internal pure returns (uint80 ret, uint nextOffset) {
    (ret, nextOffset) = asUint80Unchecked(encoded, offset);
    checkBound(nextOffset, encoded.length);
  }

  function asBytes10Unchecked(
    bytes memory encoded,
    uint offset
  ) internal pure returns (bytes10, uint) {
    (uint80 ret, uint nextOffset) = asUint80Unchecked(encoded, offset);
    return (bytes10(ret), nextOffset);
  }

  function asBytes10(
    bytes memory encoded,
    uint offset
  ) internal pure returns (bytes10, uint) {
    (uint80 ret, uint nextOffset) = asUint80(encoded, offset);
    return (bytes10(ret), nextOffset);
  }

  function asUint88Unchecked(
    bytes memory encoded,
    uint offset
  ) internal pure returns (uint88 ret, uint nextOffset) {
    assembly ("memory-safe") {
      nextOffset := add(offset, 11)
      ret := mload(add(encoded, nextOffset))
    }
    return (ret, nextOffset);
  }

  function asUint88(
    bytes memory encoded,
    uint offset
  ) internal pure returns (uint88 ret, uint nextOffset) {
    (ret, nextOffset) = asUint88Unchecked(encoded, offset);
    checkBound(nextOffset, encoded.length);
  }

  function asBytes11Unchecked(
    bytes memory encoded,
    uint offset
  ) internal pure returns (bytes11, uint) {
    (uint88 ret, uint nextOffset) = asUint88Unchecked(encoded, offset);
    return (bytes11(ret), nextOffset);
  }

  function asBytes11(
    bytes memory encoded,
    uint offset
  ) internal pure returns (bytes11, uint) {
    (uint88 ret, uint nextOffset) = asUint88(encoded, offset);
    return (bytes11(ret), nextOffset);
  }

  function asUint96Unchecked(
    bytes memory encoded,
    uint offset
  ) internal pure returns (uint96 ret, uint nextOffset) {
    assembly ("memory-safe") {
      nextOffset := add(offset, 12)
      ret := mload(add(encoded, nextOffset))
    }
    return (ret, nextOffset);
  }

  function asUint96(
    bytes memory encoded,
    uint offset
  ) internal pure returns (uint96 ret, uint nextOffset) {
    (ret, nextOffset) = asUint96Unchecked(encoded, offset);
    checkBound(nextOffset, encoded.length);
  }

  function asBytes12Unchecked(
    bytes memory encoded,
    uint offset
  ) internal pure returns (bytes12, uint) {
    (uint96 ret, uint nextOffset) = asUint96Unchecked(encoded, offset);
    return (bytes12(ret), nextOffset);
  }

  function asBytes12(
    bytes memory encoded,
    uint offset
  ) internal pure returns (bytes12, uint) {
    (uint96 ret, uint nextOffset) = asUint96(encoded, offset);
    return (bytes12(ret), nextOffset);
  }

  function asUint104Unchecked(
    bytes memory encoded,
    uint offset
  ) internal pure returns (uint104 ret, uint nextOffset) {
    assembly ("memory-safe") {
      nextOffset := add(offset, 13)
      ret := mload(add(encoded, nextOffset))
    }
    return (ret, nextOffset);
  }

  function asUint104(
    bytes memory encoded,
    uint offset
  ) internal pure returns (uint104 ret, uint nextOffset) {
    (ret, nextOffset) = asUint104Unchecked(encoded, offset);
    checkBound(nextOffset, encoded.length);
  }

  function asBytes13Unchecked(
    bytes memory encoded,
    uint offset
  ) internal pure returns (bytes13, uint) {
    (uint104 ret, uint nextOffset) = asUint104Unchecked(encoded, offset);
    return (bytes13(ret), nextOffset);
  }

  function asBytes13(
    bytes memory encoded,
    uint offset
  ) internal pure returns (bytes13, uint) {
    (uint104 ret, uint nextOffset) = asUint104(encoded, offset);
    return (bytes13(ret), nextOffset);
  }

  function asUint112Unchecked(
    bytes memory encoded,
    uint offset
  ) internal pure returns (uint112 ret, uint nextOffset) {
    assembly ("memory-safe") {
      nextOffset := add(offset, 14)
      ret := mload(add(encoded, nextOffset))
    }
    return (ret, nextOffset);
  }

  function asUint112(
    bytes memory encoded,
    uint offset
  ) internal pure returns (uint112 ret, uint nextOffset) {
    (ret, nextOffset) = asUint112Unchecked(encoded, offset);
    checkBound(nextOffset, encoded.length);
  }

  function asBytes14Unchecked(
    bytes memory encoded,
    uint offset
  ) internal pure returns (bytes14, uint) {
    (uint112 ret, uint nextOffset) = asUint112Unchecked(encoded, offset);
    return (bytes14(ret), nextOffset);
  }

  function asBytes14(
    bytes memory encoded,
    uint offset
  ) internal pure returns (bytes14, uint) {
    (uint112 ret, uint nextOffset) = asUint112(encoded, offset);
    return (bytes14(ret), nextOffset);
  }

  function asUint120Unchecked(
    bytes memory encoded,
    uint offset
  ) internal pure returns (uint120 ret, uint nextOffset) {
    assembly ("memory-safe") {
      nextOffset := add(offset, 15)
      ret := mload(add(encoded, nextOffset))
    }
    return (ret, nextOffset);
  }

  function asUint120(
    bytes memory encoded,
    uint offset
  ) internal pure returns (uint120 ret, uint nextOffset) {
    (ret, nextOffset) = asUint120Unchecked(encoded, offset);
    checkBound(nextOffset, encoded.length);
  }

  function asBytes15Unchecked(
    bytes memory encoded,
    uint offset
  ) internal pure returns (bytes15, uint) {
    (uint120 ret, uint nextOffset) = asUint120Unchecked(encoded, offset);
    return (bytes15(ret), nextOffset);
  }

  function asBytes15(
    bytes memory encoded,
    uint offset
  ) internal pure returns (bytes15, uint) {
    (uint120 ret, uint nextOffset) = asUint120(encoded, offset);
    return (bytes15(ret), nextOffset);
  }

  function asUint128Unchecked(
    bytes memory encoded,
    uint offset
  ) internal pure returns (uint128 ret, uint nextOffset) {
    assembly ("memory-safe") {
      nextOffset := add(offset, 16)
      ret := mload(add(encoded, nextOffset))
    }
    return (ret, nextOffset);
  }

  function asUint128(
    bytes memory encoded,
    uint offset
  ) internal pure returns (uint128 ret, uint nextOffset) {
    (ret, nextOffset) = asUint128Unchecked(encoded, offset);
    checkBound(nextOffset, encoded.length);
  }

  function asBytes16Unchecked(
    bytes memory encoded,
    uint offset
  ) internal pure returns (bytes16, uint) {
    (uint128 ret, uint nextOffset) = asUint128Unchecked(encoded, offset);
    return (bytes16(ret), nextOffset);
  }

  function asBytes16(
    bytes memory encoded,
    uint offset
  ) internal pure returns (bytes16, uint) {
    (uint128 ret, uint nextOffset) = asUint128(encoded, offset);
    return (bytes16(ret), nextOffset);
  }

  function asUint136Unchecked(
    bytes memory encoded,
    uint offset
  ) internal pure returns (uint136 ret, uint nextOffset) {
    assembly ("memory-safe") {
      nextOffset := add(offset, 17)
      ret := mload(add(encoded, nextOffset))
    }
    return (ret, nextOffset);
  }

  function asUint136(
    bytes memory encoded,
    uint offset
  ) internal pure returns (uint136 ret, uint nextOffset) {
    (ret, nextOffset) = asUint136Unchecked(encoded, offset);
    checkBound(nextOffset, encoded.length);
  }

  function asBytes17Unchecked(
    bytes memory encoded,
    uint offset
  ) internal pure returns (bytes17, uint) {
    (uint136 ret, uint nextOffset) = asUint136Unchecked(encoded, offset);
    return (bytes17(ret), nextOffset);
  }

  function asBytes17(
    bytes memory encoded,
    uint offset
  ) internal pure returns (bytes17, uint) {
    (uint136 ret, uint nextOffset) = asUint136(encoded, offset);
    return (bytes17(ret), nextOffset);
  }

  function asUint144Unchecked(
    bytes memory encoded,
    uint offset
  ) internal pure returns (uint144 ret, uint nextOffset) {
    assembly ("memory-safe") {
      nextOffset := add(offset, 18)
      ret := mload(add(encoded, nextOffset))
    }
    return (ret, nextOffset);
  }

  function asUint144(
    bytes memory encoded,
    uint offset
  ) internal pure returns (uint144 ret, uint nextOffset) {
    (ret, nextOffset) = asUint144Unchecked(encoded, offset);
    checkBound(nextOffset, encoded.length);
  }

  function asBytes18Unchecked(
    bytes memory encoded,
    uint offset
  ) internal pure returns (bytes18, uint) {
    (uint144 ret, uint nextOffset) = asUint144Unchecked(encoded, offset);
    return (bytes18(ret), nextOffset);
  }

  function asBytes18(
    bytes memory encoded,
    uint offset
  ) internal pure returns (bytes18, uint) {
    (uint144 ret, uint nextOffset) = asUint144(encoded, offset);
    return (bytes18(ret), nextOffset);
  }

  function asUint152Unchecked(
    bytes memory encoded,
    uint offset
  ) internal pure returns (uint152 ret, uint nextOffset) {
    assembly ("memory-safe") {
      nextOffset := add(offset, 19)
      ret := mload(add(encoded, nextOffset))
    }
    return (ret, nextOffset);
  }

  function asUint152(
    bytes memory encoded,
    uint offset
  ) internal pure returns (uint152 ret, uint nextOffset) {
    (ret, nextOffset) = asUint152Unchecked(encoded, offset);
    checkBound(nextOffset, encoded.length);
  }

  function asBytes19Unchecked(
    bytes memory encoded,
    uint offset
  ) internal pure returns (bytes19, uint) {
    (uint152 ret, uint nextOffset) = asUint152Unchecked(encoded, offset);
    return (bytes19(ret), nextOffset);
  }

  function asBytes19(
    bytes memory encoded,
    uint offset
  ) internal pure returns (bytes19, uint) {
    (uint152 ret, uint nextOffset) = asUint152(encoded, offset);
    return (bytes19(ret), nextOffset);
  }

  function asUint160Unchecked(
    bytes memory encoded,
    uint offset
  ) internal pure returns (uint160 ret, uint nextOffset) {
    assembly ("memory-safe") {
      nextOffset := add(offset, 20)
      ret := mload(add(encoded, nextOffset))
    }
    return (ret, nextOffset);
  }

  function asUint160(
    bytes memory encoded,
    uint offset
  ) internal pure returns (uint160 ret, uint nextOffset) {
    (ret, nextOffset) = asUint160Unchecked(encoded, offset);
    checkBound(nextOffset, encoded.length);
  }

  function asBytes20Unchecked(
    bytes memory encoded,
    uint offset
  ) internal pure returns (bytes20, uint) {
    (uint160 ret, uint nextOffset) = asUint160Unchecked(encoded, offset);
    return (bytes20(ret), nextOffset);
  }

  function asBytes20(
    bytes memory encoded,
    uint offset
  ) internal pure returns (bytes20, uint) {
    (uint160 ret, uint nextOffset) = asUint160(encoded, offset);
    return (bytes20(ret), nextOffset);
  }

  function asUint168Unchecked(
    bytes memory encoded,
    uint offset
  ) internal pure returns (uint168 ret, uint nextOffset) {
    assembly ("memory-safe") {
      nextOffset := add(offset, 21)
      ret := mload(add(encoded, nextOffset))
    }
    return (ret, nextOffset);
  }

  function asUint168(
    bytes memory encoded,
    uint offset
  ) internal pure returns (uint168 ret, uint nextOffset) {
    (ret, nextOffset) = asUint168Unchecked(encoded, offset);
    checkBound(nextOffset, encoded.length);
  }

  function asBytes21Unchecked(
    bytes memory encoded,
    uint offset
  ) internal pure returns (bytes21, uint) {
    (uint168 ret, uint nextOffset) = asUint168Unchecked(encoded, offset);
    return (bytes21(ret), nextOffset);
  }

  function asBytes21(
    bytes memory encoded,
    uint offset
  ) internal pure returns (bytes21, uint) {
    (uint168 ret, uint nextOffset) = asUint168(encoded, offset);
    return (bytes21(ret), nextOffset);
  }

  function asUint176Unchecked(
    bytes memory encoded,
    uint offset
  ) internal pure returns (uint176 ret, uint nextOffset) {
    assembly ("memory-safe") {
      nextOffset := add(offset, 22)
      ret := mload(add(encoded, nextOffset))
    }
    return (ret, nextOffset);
  }

  function asUint176(
    bytes memory encoded,
    uint offset
  ) internal pure returns (uint176 ret, uint nextOffset) {
    (ret, nextOffset) = asUint176Unchecked(encoded, offset);
    checkBound(nextOffset, encoded.length);
  }

  function asBytes22Unchecked(
    bytes memory encoded,
    uint offset
  ) internal pure returns (bytes22, uint) {
    (uint176 ret, uint nextOffset) = asUint176Unchecked(encoded, offset);
    return (bytes22(ret), nextOffset);
  }

  function asBytes22(
    bytes memory encoded,
    uint offset
  ) internal pure returns (bytes22, uint) {
    (uint176 ret, uint nextOffset) = asUint176(encoded, offset);
    return (bytes22(ret), nextOffset);
  }

  function asUint184Unchecked(
    bytes memory encoded,
    uint offset
  ) internal pure returns (uint184 ret, uint nextOffset) {
    assembly ("memory-safe") {
      nextOffset := add(offset, 23)
      ret := mload(add(encoded, nextOffset))
    }
    return (ret, nextOffset);
  }

  function asUint184(
    bytes memory encoded,
    uint offset
  ) internal pure returns (uint184 ret, uint nextOffset) {
    (ret, nextOffset) = asUint184Unchecked(encoded, offset);
    checkBound(nextOffset, encoded.length);
  }

  function asBytes23Unchecked(
    bytes memory encoded,
    uint offset
  ) internal pure returns (bytes23, uint) {
    (uint184 ret, uint nextOffset) = asUint184Unchecked(encoded, offset);
    return (bytes23(ret), nextOffset);
  }

  function asBytes23(
    bytes memory encoded,
    uint offset
  ) internal pure returns (bytes23, uint) {
    (uint184 ret, uint nextOffset) = asUint184(encoded, offset);
    return (bytes23(ret), nextOffset);
  }

  function asUint192Unchecked(
    bytes memory encoded,
    uint offset
  ) internal pure returns (uint192 ret, uint nextOffset) {
    assembly ("memory-safe") {
      nextOffset := add(offset, 24)
      ret := mload(add(encoded, nextOffset))
    }
    return (ret, nextOffset);
  }

  function asUint192(
    bytes memory encoded,
    uint offset
  ) internal pure returns (uint192 ret, uint nextOffset) {
    (ret, nextOffset) = asUint192Unchecked(encoded, offset);
    checkBound(nextOffset, encoded.length);
  }

  function asBytes24Unchecked(
    bytes memory encoded,
    uint offset
  ) internal pure returns (bytes24, uint) {
    (uint192 ret, uint nextOffset) = asUint192Unchecked(encoded, offset);
    return (bytes24(ret), nextOffset);
  }

  function asBytes24(
    bytes memory encoded,
    uint offset
  ) internal pure returns (bytes24, uint) {
    (uint192 ret, uint nextOffset) = asUint192(encoded, offset);
    return (bytes24(ret), nextOffset);
  }

  function asUint200Unchecked(
    bytes memory encoded,
    uint offset
  ) internal pure returns (uint200 ret, uint nextOffset) {
    assembly ("memory-safe") {
      nextOffset := add(offset, 25)
      ret := mload(add(encoded, nextOffset))
    }
    return (ret, nextOffset);
  }

  function asUint200(
    bytes memory encoded,
    uint offset
  ) internal pure returns (uint200 ret, uint nextOffset) {
    (ret, nextOffset) = asUint200Unchecked(encoded, offset);
    checkBound(nextOffset, encoded.length);
  }

  function asBytes25Unchecked(
    bytes memory encoded,
    uint offset
  ) internal pure returns (bytes25, uint) {
    (uint200 ret, uint nextOffset) = asUint200Unchecked(encoded, offset);
    return (bytes25(ret), nextOffset);
  }

  function asBytes25(
    bytes memory encoded,
    uint offset
  ) internal pure returns (bytes25, uint) {
    (uint200 ret, uint nextOffset) = asUint200(encoded, offset);
    return (bytes25(ret), nextOffset);
  }

  function asUint208Unchecked(
    bytes memory encoded,
    uint offset
  ) internal pure returns (uint208 ret, uint nextOffset) {
    assembly ("memory-safe") {
      nextOffset := add(offset, 26)
      ret := mload(add(encoded, nextOffset))
    }
    return (ret, nextOffset);
  }

  function asUint208(
    bytes memory encoded,
    uint offset
  ) internal pure returns (uint208 ret, uint nextOffset) {
    (ret, nextOffset) = asUint208Unchecked(encoded, offset);
    checkBound(nextOffset, encoded.length);
  }

  function asBytes26Unchecked(
    bytes memory encoded,
    uint offset
  ) internal pure returns (bytes26, uint) {
    (uint208 ret, uint nextOffset) = asUint208Unchecked(encoded, offset);
    return (bytes26(ret), nextOffset);
  }

  function asBytes26(
    bytes memory encoded,
    uint offset
  ) internal pure returns (bytes26, uint) {
    (uint208 ret, uint nextOffset) = asUint208(encoded, offset);
    return (bytes26(ret), nextOffset);
  }

  function asUint216Unchecked(
    bytes memory encoded,
    uint offset
  ) internal pure returns (uint216 ret, uint nextOffset) {
    assembly ("memory-safe") {
      nextOffset := add(offset, 27)
      ret := mload(add(encoded, nextOffset))
    }
    return (ret, nextOffset);
  }

  function asUint216(
    bytes memory encoded,
    uint offset
  ) internal pure returns (uint216 ret, uint nextOffset) {
    (ret, nextOffset) = asUint216Unchecked(encoded, offset);
    checkBound(nextOffset, encoded.length);
  }

  function asBytes27Unchecked(
    bytes memory encoded,
    uint offset
  ) internal pure returns (bytes27, uint) {
    (uint216 ret, uint nextOffset) = asUint216Unchecked(encoded, offset);
    return (bytes27(ret), nextOffset);
  }

  function asBytes27(
    bytes memory encoded,
    uint offset
  ) internal pure returns (bytes27, uint) {
    (uint216 ret, uint nextOffset) = asUint216(encoded, offset);
    return (bytes27(ret), nextOffset);
  }

  function asUint224Unchecked(
    bytes memory encoded,
    uint offset
  ) internal pure returns (uint224 ret, uint nextOffset) {
    assembly ("memory-safe") {
      nextOffset := add(offset, 28)
      ret := mload(add(encoded, nextOffset))
    }
    return (ret, nextOffset);
  }

  function asUint224(
    bytes memory encoded,
    uint offset
  ) internal pure returns (uint224 ret, uint nextOffset) {
    (ret, nextOffset) = asUint224Unchecked(encoded, offset);
    checkBound(nextOffset, encoded.length);
  }

  function asBytes28Unchecked(
    bytes memory encoded,
    uint offset
  ) internal pure returns (bytes28, uint) {
    (uint224 ret, uint nextOffset) = asUint224Unchecked(encoded, offset);
    return (bytes28(ret), nextOffset);
  }

  function asBytes28(
    bytes memory encoded,
    uint offset
  ) internal pure returns (bytes28, uint) {
    (uint224 ret, uint nextOffset) = asUint224(encoded, offset);
    return (bytes28(ret), nextOffset);
  }

  function asUint232Unchecked(
    bytes memory encoded,
    uint offset
  ) internal pure returns (uint232 ret, uint nextOffset) {
    assembly ("memory-safe") {
      nextOffset := add(offset, 29)
      ret := mload(add(encoded, nextOffset))
    }
    return (ret, nextOffset);
  }

  function asUint232(
    bytes memory encoded,
    uint offset
  ) internal pure returns (uint232 ret, uint nextOffset) {
    (ret, nextOffset) = asUint232Unchecked(encoded, offset);
    checkBound(nextOffset, encoded.length);
  }

  function asBytes29Unchecked(
    bytes memory encoded,
    uint offset
  ) internal pure returns (bytes29, uint) {
    (uint232 ret, uint nextOffset) = asUint232Unchecked(encoded, offset);
    return (bytes29(ret), nextOffset);
  }

  function asBytes29(
    bytes memory encoded,
    uint offset
  ) internal pure returns (bytes29, uint) {
    (uint232 ret, uint nextOffset) = asUint232(encoded, offset);
    return (bytes29(ret), nextOffset);
  }

  function asUint240Unchecked(
    bytes memory encoded,
    uint offset
  ) internal pure returns (uint240 ret, uint nextOffset) {
    assembly ("memory-safe") {
      nextOffset := add(offset, 30)
      ret := mload(add(encoded, nextOffset))
    }
    return (ret, nextOffset);
  }

  function asUint240(
    bytes memory encoded,
    uint offset
  ) internal pure returns (uint240 ret, uint nextOffset) {
    (ret, nextOffset) = asUint240Unchecked(encoded, offset);
    checkBound(nextOffset, encoded.length);
  }

  function asBytes30Unchecked(
    bytes memory encoded,
    uint offset
  ) internal pure returns (bytes30, uint) {
    (uint240 ret, uint nextOffset) = asUint240Unchecked(encoded, offset);
    return (bytes30(ret), nextOffset);
  }

  function asBytes30(
    bytes memory encoded,
    uint offset
  ) internal pure returns (bytes30, uint) {
    (uint240 ret, uint nextOffset) = asUint240(encoded, offset);
    return (bytes30(ret), nextOffset);
  }

  function asUint248Unchecked(
    bytes memory encoded,
    uint offset
  ) internal pure returns (uint248 ret, uint nextOffset) {
    assembly ("memory-safe") {
      nextOffset := add(offset, 31)
      ret := mload(add(encoded, nextOffset))
    }
    return (ret, nextOffset);
  }

  function asUint248(
    bytes memory encoded,
    uint offset
  ) internal pure returns (uint248 ret, uint nextOffset) {
    (ret, nextOffset) = asUint248Unchecked(encoded, offset);
    checkBound(nextOffset, encoded.length);
  }

  function asBytes31Unchecked(
    bytes memory encoded,
    uint offset
  ) internal pure returns (bytes31, uint) {
    (uint248 ret, uint nextOffset) = asUint248Unchecked(encoded, offset);
    return (bytes31(ret), nextOffset);
  }

  function asBytes31(
    bytes memory encoded,
    uint offset
  ) internal pure returns (bytes31, uint) {
    (uint248 ret, uint nextOffset) = asUint248(encoded, offset);
    return (bytes31(ret), nextOffset);
  }

  function asUint256Unchecked(
    bytes memory encoded,
    uint offset
  ) internal pure returns (uint256 ret, uint nextOffset) {
    assembly ("memory-safe") {
      nextOffset := add(offset, 32)
      ret := mload(add(encoded, nextOffset))
    }
    return (ret, nextOffset);
  }

  function asUint256(
    bytes memory encoded,
    uint offset
  ) internal pure returns (uint256 ret, uint nextOffset) {
    (ret, nextOffset) = asUint256Unchecked(encoded, offset);
    checkBound(nextOffset, encoded.length);
  }

  function asBytes32Unchecked(
    bytes memory encoded,
    uint offset
  ) internal pure returns (bytes32, uint) {
    (uint256 ret, uint nextOffset) = asUint256Unchecked(encoded, offset);
    return (bytes32(ret), nextOffset);
  }

  function asBytes32(
    bytes memory encoded,
    uint offset
  ) internal pure returns (bytes32, uint) {
    (uint256 ret, uint nextOffset) = asUint256(encoded, offset);
    return (bytes32(ret), nextOffset);
  }
}

error UnexpectedExecutionParamsVersion(uint8 version, uint8 expectedVersion);
error UnsupportedExecutionParamsVersion(uint8 version);
error TargetChainAndExecutionParamsVersionMismatch(uint16 targetChain, uint8 version);
error UnexpectedExecutionInfoVersion(uint8 version, uint8 expectedVersion);
error UnsupportedExecutionInfoVersion(uint8 version);
error TargetChainAndExecutionInfoVersionMismatch(uint16 targetChain, uint8 version);
error VersionMismatchOverride(uint8 instructionVersion, uint8 overrideVersion);

using BytesParsing for bytes;

enum ExecutionParamsVersion {EVM_V1}

struct EvmExecutionParamsV1 {
    Gas gasLimit;
}

enum ExecutionInfoVersion {EVM_V1}

struct EvmExecutionInfoV1 {
    Gas gasLimit;
    GasPrice targetChainRefundPerGasUnused;
}

function decodeExecutionParamsVersion(bytes memory data)
    pure
    returns (ExecutionParamsVersion version)
{
    (version) = abi.decode(data, (ExecutionParamsVersion));
}

function decodeExecutionInfoVersion(bytes memory data)
    pure
    returns (ExecutionInfoVersion version)
{
    (version) = abi.decode(data, (ExecutionInfoVersion));
}

function encodeEvmExecutionParamsV1(EvmExecutionParamsV1 memory executionParams)
    pure
    returns (bytes memory)
{
    return abi.encode(uint8(ExecutionParamsVersion.EVM_V1), executionParams.gasLimit);
}

function decodeEvmExecutionParamsV1(bytes memory data)
    pure
    returns (EvmExecutionParamsV1 memory executionParams)
{
    uint8 version;
    (version, executionParams.gasLimit) = abi.decode(data, (uint8, Gas));

    if (version != uint8(ExecutionParamsVersion.EVM_V1)) {
        revert UnexpectedExecutionParamsVersion(version, uint8(ExecutionParamsVersion.EVM_V1));
    }
}

function encodeEvmExecutionInfoV1(EvmExecutionInfoV1 memory executionInfo)
    pure
    returns (bytes memory)
{
    return abi.encode(
        uint8(ExecutionInfoVersion.EVM_V1),
        executionInfo.gasLimit,
        executionInfo.targetChainRefundPerGasUnused
    );
}

function decodeEvmExecutionInfoV1(bytes memory data)
    pure
    returns (EvmExecutionInfoV1 memory executionInfo)
{
    uint8 version;
    (version, executionInfo.gasLimit, executionInfo.targetChainRefundPerGasUnused) =
        abi.decode(data, (uint8, Gas, GasPrice));

    if (version != uint8(ExecutionInfoVersion.EVM_V1)) {
        revert UnexpectedExecutionInfoVersion(version, uint8(ExecutionInfoVersion.EVM_V1));
    }
}

function getEmptyEvmExecutionParamsV1()
    pure
    returns (EvmExecutionParamsV1 memory executionParams)
{
    executionParams.gasLimit = Gas.wrap(uint256(0));
}

interface IDeliveryProvider {
    
    /**
     * @notice This function returns 
     *
     * 1) nativePriceQuote: the price of a delivery (by this delivery provider) to chain
     * 'targetChain', giving the user's contract 'receiverValue' target chain wei and performing the 
     * relay with the execution parameters (e.g. the gas limit) specified in 'encodedExecutionParameters'
     * 
     * 2) encodedExecutionInfo: information relating to how this delivery provider
     * will perform such a delivery (e.g. the gas limit, and the amount it will refund per gas unused)
     *
     * encodedExecutionParameters and encodedExecutionInfo both are encodings of versioned structs - 
     * version EVM_V1 of ExecutionParameters specifies the gas limit,
     * and version EVM_V1 of ExecutionInfo specifies the gas limit and the amount that this delivery provider 
     * will refund per unit of gas unused
     */
    function quoteDeliveryPrice(
        uint16 targetChain,
        TargetNative receiverValue,
        bytes memory encodedExecutionParams
    ) external view returns (LocalNative nativePriceQuote, bytes memory encodedExecutionInfo);

    /**
     * @notice This function returns the amount of extra 'receiverValue' (msg.value on the target chain) 
     * that will be sent to your contract, if you specify 'currentChainAmount' in the 
     * 'paymentForExtraReceiverValue' field on 'send'
     */
    function quoteAssetConversion(
        uint16 targetChain,
        LocalNative currentChainAmount
    ) external view returns (TargetNative targetChainAmount);

    /**
     * @notice This function should return a payable address on this (source) chain where all awards
     *     should be sent for the relay provider.
     */
    function getRewardAddress() external view returns (address payable rewardAddress);

    /**
     * @notice This function determines whether a relay provider supports deliveries to a given chain
     *     or not.
     *
     * @param targetChain - The chain which is being delivered to.
     */
    function isChainSupported(uint16 targetChain) external view returns (bool supported);

    /**
     * @notice This function determines whether a relay provider supports the given keyType.
     *      
     * Note: 0-127 are reserved for standardized keyTypes and 128-255 are allowed to be custom per DeliveryProvider
     *       Practically this means that 0-127 must mean the same thing for all DeliveryProviders,
     *       while x within 128-255 may have different meanings between DeliveryProviders 
     *       (e.g. 130 for provider A means pyth price quotes while 130 for provider B means tweets, 
     *       but 8 must mean the same for both)
     *
     * @param keyType - The keyType within MessageKey that specifies what the encodedKey within a MessageKey means
     */
    function isMessageKeyTypeSupported(uint8 keyType) external view returns (bool supported);

    /**
     * @notice This function returns a bitmap encoding all the keyTypes this provider supports
     *      
     * Note: 0-127 are reserved for standardized keyTypes and 128-255 are allowed to be custom per DeliveryProvider
     *       Practically this means that 0-127 must mean the same thing for all DeliveryProviders,
     *       while x within 128-255 may have different meanings between DeliveryProviders 
     *       (e.g. 130 for provider A means pyth price quotes while 130 for provider B means tweets, 
     *       but 8 must mean the same for both)
     */
    function getSupportedKeys() external view returns (uint256 bitmap);

    /**
     * @notice If a DeliveryProvider supports a given chain, this function should provide the contract
     *      address (in wormhole format) of the relay provider on that chain.
     *
     * @param targetChain - The chain which is being delivered to.
     */
    function getTargetChainAddress(uint16 targetChain)
        external
        view
        returns (bytes32 deliveryProviderAddress);
}

error NotAnEvmAddress(bytes32);

function pay(address payable receiver, LocalNative amount) returns (bool success) {
  uint256 amount_ = LocalNative.unwrap(amount);
  if (amount_ != 0)
    // TODO: we currently ignore the return data. Some users of this function might want to bubble up the return value though.
    // Specifying a higher limit than 63/64 of the remaining gas caps it at that amount without throwing an exception.
    (success,) = returnLengthBoundedCall(receiver, new bytes(0), gasleft(), amount_, 0);
  else
    success = true;
}

function pay(address payable receiver, LocalNative amount, uint256 gasBound) returns (bool success) {
  uint256 amount_ = LocalNative.unwrap(amount);
  if (amount_ != 0)
    // TODO: we currently ignore the return data. Some users of this function might want to bubble up the return value though.
    // Specifying a higher limit than 63/64 of the remaining gas caps it at that amount without throwing an exception.
    (success,) = returnLengthBoundedCall(receiver, new bytes(0), gasBound, amount_, 0);
  else
    success = true;
}

function min(uint256 a, uint256 b) pure returns (uint256) {
  return a < b ? a : b;
}

function min(uint64 a, uint64 b) pure returns (uint64) {
  return a < b ? a : b;
}

function max(uint256 a, uint256 b) pure returns (uint256) {
  return a > b ? a : b;
}

function toWormholeFormat(address addr) pure returns (bytes32) {
  return bytes32(uint256(uint160(addr)));
}

function fromWormholeFormat(bytes32 whFormatAddress) pure returns (address) {
  if (uint256(whFormatAddress) >> 160 != 0)
    revert NotAnEvmAddress(whFormatAddress);
  return address(uint160(uint256(whFormatAddress)));
}

function fromWormholeFormatUnchecked(bytes32 whFormatAddress) pure returns (address) {
  return address(uint160(uint256(whFormatAddress)));
}


uint256 constant freeMemoryPtr = 0x40;
uint256 constant memoryWord = 32;
uint256 constant maskModulo32 = 0x1f;

/**
 * Overload with no 'value' and non-payable address
 */
function returnLengthBoundedCall(
  address callee,
  bytes memory callData,
  uint256 gasLimit,
  uint256 dataLengthBound
) returns (bool success, bytes memory returnedData) {
  return returnLengthBoundedCall(payable(callee), callData, gasLimit, 0, dataLengthBound);
}

/**
 * Implements call that truncates return data to a specific size to avoid excessive gas consumption for relayers
 * when a revert or unexpectedly large return value is produced by the call.
 *
 * @param returnedData Buffer of returned data truncated to the first `dataLengthBound` bytes.
 */
function returnLengthBoundedCall(
  address payable callee,
  bytes memory callData,
  uint256 gasLimit,
  uint256 value,
  uint256 dataLengthBound
) returns (bool success, bytes memory returnedData) {
  uint256 callDataLength = callData.length;
  assembly ("memory-safe") {
    returnedData := mload(freeMemoryPtr)
    let returnedDataBuffer := add(returnedData, memoryWord)
    let callDataBuffer := add(callData, memoryWord)

    success := call(gasLimit, callee, value, callDataBuffer, callDataLength, returnedDataBuffer, dataLengthBound)
    let returnedDataSize := returndatasize()
    switch lt(dataLengthBound, returnedDataSize)
    case 1 {
      returnedDataSize := dataLengthBound
    } default {}
    mstore(returnedData, returnedDataSize)

    // Here we update the free memory pointer.
    // We want to pad `returnedData` to memory word size, i.e. 32 bytes.
    // Note that negating bitwise `maskModulo32` produces a mask that aligns addressing to 32 bytes.
    // This allows us to pad the entire `bytes` structure (length + buffer) to 32 bytes at the end.
    // We add `maskModulo32` to get the next free memory "slot" in case the `returnedDataSize` is not a multiple of the memory word size.
    //
    // Rationale:
    // We do not care about the alignment of the free memory pointer. The solidity compiler documentation does not promise nor require alignment on it.
    // It does however lightly suggest to pad `bytes` structures to 32 bytes: https://docs.soliditylang.org/en/v0.8.20/assembly.html#example
    // Searching for "alignment" and "padding" in https://gitter.im/ethereum/solidity-dev
    // yielded the following at the time of writing – paraphrased:
    // > It's possible that the compiler cleans that padding in some cases. Users should not rely on the compiler never doing that.
    // This means that we want to ensure that the free memory pointer points to memory just after this padding for our `returnedData` `bytes` structure.
    let paddedPastTheEndOffset := and(add(returnedDataSize, maskModulo32), not(maskModulo32))
    let newFreeMemoryPtr := add(returnedDataBuffer, paddedPastTheEndOffset)
    mstore(freeMemoryPtr, newFreeMemoryPtr)
  }
}

interface IWormhole {
    struct GuardianSet {
        address[] keys;
        uint32 expirationTime;
    }

    struct Signature {
        bytes32 r;
        bytes32 s;
        uint8 v;
        uint8 guardianIndex;
    }

    struct VM {
        uint8 version;
        uint32 timestamp;
        uint32 nonce;
        uint16 emitterChainId;
        bytes32 emitterAddress;
        uint64 sequence;
        uint8 consistencyLevel;
        bytes payload;

        uint32 guardianSetIndex;
        Signature[] signatures;

        bytes32 hash;
    }

    struct ContractUpgrade {
        bytes32 module;
        uint8 action;
        uint16 chain;

        address newContract;
    }

    struct GuardianSetUpgrade {
        bytes32 module;
        uint8 action;
        uint16 chain;

        GuardianSet newGuardianSet;
        uint32 newGuardianSetIndex;
    }

    struct SetMessageFee {
        bytes32 module;
        uint8 action;
        uint16 chain;

        uint256 messageFee;
    }

    struct TransferFees {
        bytes32 module;
        uint8 action;
        uint16 chain;

        uint256 amount;
        bytes32 recipient;
    }

    struct RecoverChainId {
        bytes32 module;
        uint8 action;

        uint256 evmChainId;
        uint16 newChainId;
    }

    event LogMessagePublished(address indexed sender, uint64 sequence, uint32 nonce, bytes payload, uint8 consistencyLevel);
    event ContractUpgraded(address indexed oldContract, address indexed newContract);
    event GuardianSetAdded(uint32 indexed index);

    function publishMessage(
        uint32 nonce,
        bytes memory payload,
        uint8 consistencyLevel
    ) external payable returns (uint64 sequence);

    function initialize() external;

    function parseAndVerifyVM(bytes calldata encodedVM) external view returns (VM memory vm, bool valid, string memory reason);

    function verifyVM(VM memory vm) external view returns (bool valid, string memory reason);

    function verifySignatures(bytes32 hash, Signature[] memory signatures, GuardianSet memory guardianSet) external pure returns (bool valid, string memory reason);

    function parseVM(bytes memory encodedVM) external pure returns (VM memory vm);

    function quorum(uint numGuardians) external pure returns (uint numSignaturesRequiredForQuorum);

    function getGuardianSet(uint32 index) external view returns (GuardianSet memory);

    function getCurrentGuardianSetIndex() external view returns (uint32);

    function getGuardianSetExpiry() external view returns (uint32);

    function governanceActionIsConsumed(bytes32 hash) external view returns (bool);

    function isInitialized(address impl) external view returns (bool);

    function chainId() external view returns (uint16);

    function isFork() external view returns (bool);

    function governanceChainId() external view returns (uint16);

    function governanceContract() external view returns (bytes32);

    function messageFee() external view returns (uint256);

    function evmChainId() external view returns (uint256);

    function nextSequence(address emitter) external view returns (uint64);

    function parseContractUpgrade(bytes memory encodedUpgrade) external pure returns (ContractUpgrade memory cu);

    function parseGuardianSetUpgrade(bytes memory encodedUpgrade) external pure returns (GuardianSetUpgrade memory gsu);

    function parseSetMessageFee(bytes memory encodedSetMessageFee) external pure returns (SetMessageFee memory smf);

    function parseTransferFees(bytes memory encodedTransferFees) external pure returns (TransferFees memory tf);

    function parseRecoverChainId(bytes memory encodedRecoverChainId) external pure returns (RecoverChainId memory rci);

    function submitContractUpgrade(bytes memory _vm) external;

    function submitSetMessageFee(bytes memory _vm) external;

    function submitNewGuardianSet(bytes memory _vm) external;

    function submitTransferFees(bytes memory _vm) external;

    function submitRecoverChainId(bytes memory _vm) external;
}

/**
 * @dev This abstract contract provides getters and event emitting update functions for
 * https://eips.ethereum.org/EIPS/eip-1967[EIP1967] slots.
 *
 * _Available since v4.1._
 *
 * @custom:oz-upgrades-unsafe-allow delegatecall
 */
abstract contract ERC1967Upgrade {
    // This is the keccak-256 hash of "eip1967.proxy.rollback" subtracted by 1
    bytes32 private constant _ROLLBACK_SLOT = 0x4910fdfa16fed3260ed0e7147f7cc6da11a60208b5b9406d12a635614ffd9143;

    /**
     * @dev Storage slot with the address of the current implementation.
     * This is the keccak-256 hash of "eip1967.proxy.implementation" subtracted by 1, and is
     * validated in the constructor.
     */
    bytes32 internal constant _IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    /**
     * @dev Emitted when the implementation is upgraded.
     */
    event Upgraded(address indexed implementation);

    /**
     * @dev Returns the current implementation address.
     */
    function _getImplementation() internal view returns (address) {
        return StorageSlot.getAddressSlot(_IMPLEMENTATION_SLOT).value;
    }

    /**
     * @dev Stores a new address in the EIP1967 implementation slot.
     */
    function _setImplementation(address newImplementation) private {
        require(Address.isContract(newImplementation), "ERC1967: new implementation is not a contract");
        StorageSlot.getAddressSlot(_IMPLEMENTATION_SLOT).value = newImplementation;
    }

    /**
     * @dev Perform implementation upgrade
     *
     * Emits an {Upgraded} event.
     */
    function _upgradeTo(address newImplementation) internal {
        _setImplementation(newImplementation);
        emit Upgraded(newImplementation);
    }

    /**
     * @dev Perform implementation upgrade with additional setup call.
     *
     * Emits an {Upgraded} event.
     */
    function _upgradeToAndCall(
        address newImplementation,
        bytes memory data,
        bool forceCall
    ) internal {
        _upgradeTo(newImplementation);
        if (data.length > 0 || forceCall) {
            Address.functionDelegateCall(newImplementation, data);
        }
    }

    /**
     * @dev Perform implementation upgrade with security checks for UUPS proxies, and additional setup call.
     *
     * Emits an {Upgraded} event.
     */
    function _upgradeToAndCallSecure(
        address newImplementation,
        bytes memory data,
        bool forceCall
    ) internal {
        address oldImplementation = _getImplementation();

        // Initial upgrade and setup call
        _setImplementation(newImplementation);
        if (data.length > 0 || forceCall) {
            Address.functionDelegateCall(newImplementation, data);
        }

        // Perform rollback test if not already in progress
        StorageSlot.BooleanSlot storage rollbackTesting = StorageSlot.getBooleanSlot(_ROLLBACK_SLOT);
        if (!rollbackTesting.value) {
            // Trigger rollback using upgradeTo from the new implementation
            rollbackTesting.value = true;
            Address.functionDelegateCall(
                newImplementation,
                abi.encodeWithSignature("upgradeTo(address)", oldImplementation)
            );
            rollbackTesting.value = false;
            // Check rollback was effective
            require(oldImplementation == _getImplementation(), "ERC1967Upgrade: upgrade breaks further upgrades");
            // Finally reset to the new implementation and log the upgrade
            _upgradeTo(newImplementation);
        }
    }

    /**
     * @dev Storage slot with the admin of the contract.
     * This is the keccak-256 hash of "eip1967.proxy.admin" subtracted by 1, and is
     * validated in the constructor.
     */
    bytes32 internal constant _ADMIN_SLOT = 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;

    /**
     * @dev Emitted when the admin account has changed.
     */
    event AdminChanged(address previousAdmin, address newAdmin);

    /**
     * @dev Returns the current admin.
     */
    function _getAdmin() internal view returns (address) {
        return StorageSlot.getAddressSlot(_ADMIN_SLOT).value;
    }

    /**
     * @dev Stores a new address in the EIP1967 admin slot.
     */
    function _setAdmin(address newAdmin) private {
        require(newAdmin != address(0), "ERC1967: new admin is the zero address");
        StorageSlot.getAddressSlot(_ADMIN_SLOT).value = newAdmin;
    }

    /**
     * @dev Changes the admin of the proxy.
     *
     * Emits an {AdminChanged} event.
     */
    function _changeAdmin(address newAdmin) internal {
        emit AdminChanged(_getAdmin(), newAdmin);
        _setAdmin(newAdmin);
    }

    /**
     * @dev The storage slot of the UpgradeableBeacon contract which defines the implementation for this proxy.
     * This is bytes32(uint256(keccak256('eip1967.proxy.beacon')) - 1)) and is validated in the constructor.
     */
    bytes32 internal constant _BEACON_SLOT = 0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50;

    /**
     * @dev Emitted when the beacon is upgraded.
     */
    event BeaconUpgraded(address indexed beacon);

    /**
     * @dev Returns the current beacon.
     */
    function _getBeacon() internal view returns (address) {
        return StorageSlot.getAddressSlot(_BEACON_SLOT).value;
    }

    /**
     * @dev Stores a new beacon in the EIP1967 beacon slot.
     */
    function _setBeacon(address newBeacon) private {
        require(Address.isContract(newBeacon), "ERC1967: new beacon is not a contract");
        require(
            Address.isContract(IBeacon(newBeacon).implementation()),
            "ERC1967: beacon implementation is not a contract"
        );
        StorageSlot.getAddressSlot(_BEACON_SLOT).value = newBeacon;
    }

    /**
     * @dev Perform beacon upgrade with additional setup call. Note: This upgrades the address of the beacon, it does
     * not upgrade the implementation contained in the beacon (see {UpgradeableBeacon-_setImplementation} for that).
     *
     * Emits a {BeaconUpgraded} event.
     */
    function _upgradeBeaconToAndCall(
        address newBeacon,
        bytes memory data,
        bool forceCall
    ) internal {
        _setBeacon(newBeacon);
        emit BeaconUpgraded(newBeacon);
        if (data.length > 0 || forceCall) {
            Address.functionDelegateCall(IBeacon(newBeacon).implementation(), data);
        }
    }
}

/**
 * @title WormholeRelayer
 * @author 
 * @notice This project allows developers to build cross-chain applications powered by Wormhole without needing to 
 * write and run their own relaying infrastructure
 * 
 * We implement the IWormholeRelayer interface that allows users to request a delivery provider to relay a payload (and/or additional messages) 
 * to a chain and address of their choice.
 */

/**
 * @notice VaaKey identifies a wormhole message
 *
 * @custom:member chainId Wormhole chain ID of the chain where this VAA was emitted from
 * @custom:member emitterAddress Address of the emitter of the VAA, in Wormhole bytes32 format
 * @custom:member sequence Sequence number of the VAA
 */
struct VaaKey {
    uint16 chainId;
    bytes32 emitterAddress;
    uint64 sequence;
}

// 0-127 are reserved for standardized KeyTypes, 128-255 are for custom use
uint8 constant VAA_KEY_TYPE = 1;

struct MessageKey {
    uint8 keyType; // 0-127 are reserved for standardized KeyTypes, 128-255 are for custom use
    bytes encodedKey;
}


interface IWormholeRelayerBase {
    event SendEvent(
        uint64 indexed sequence, LocalNative deliveryQuote, LocalNative paymentForExtraReceiverValue
    );

    function getRegisteredWormholeRelayerContract(uint16 chainId) external view returns (bytes32);

    /**
     * @notice Returns true if a delivery has been attempted for the given deliveryHash
     * Note: invalid deliveries where the tx reverts are not considered attempted
     */
    function deliveryAttempted(bytes32 deliveryHash) external view returns (bool attempted);

    /**
     * @notice block number at which a delivery was successfully executed
     */
    function deliverySuccessBlock(bytes32 deliveryHash) external view returns (uint256 blockNumber);

    /**
     * @notice block number of the latest attempt to execute a delivery that failed
     */
    function deliveryFailureBlock(bytes32 deliveryHash) external view returns (uint256 blockNumber);
}

/**
 * @title IWormholeRelayerSend
 * @notice The interface to request deliveries
 */
interface IWormholeRelayerSend is IWormholeRelayerBase {

    /**
     * @notice Publishes an instruction for the default delivery provider
     * to relay a payload to the address `targetAddress` on chain `targetChain` 
     * with gas limit `gasLimit` and `msg.value` equal to `receiverValue`
     * 
     * `targetAddress` must implement the IWormholeReceiver interface
     * 
     * This function must be called with `msg.value` equal to `quoteEVMDeliveryPrice(targetChain, receiverValue, gasLimit)`
     * 
     * Any refunds (from leftover gas) will be paid to the delivery provider. In order to receive the refunds, use the `sendPayloadToEvm` function 
     * with `refundChain` and `refundAddress` as parameters
     * 
     * @param targetChain in Wormhole Chain ID format
     * @param targetAddress address to call on targetChain (that implements IWormholeReceiver) 
     * @param payload arbitrary bytes to pass in as parameter in call to `targetAddress`
     * @param receiverValue msg.value that delivery provider should pass in for call to `targetAddress` (in targetChain currency units)
     * @param gasLimit gas limit with which to call `targetAddress`.
     * @return sequence sequence number of published VAA containing delivery instructions
     */
    function sendPayloadToEvm(
        uint16 targetChain,
        address targetAddress,
        bytes memory payload,
        TargetNative receiverValue,
        Gas gasLimit
    ) external payable returns (uint64 sequence);

    /**
     * @notice Publishes an instruction for the default delivery provider
     * to relay a payload to the address `targetAddress` on chain `targetChain` 
     * with gas limit `gasLimit` and `msg.value` equal to `receiverValue`
     * 
     * Any refunds (from leftover gas) will be sent to `refundAddress` on chain `refundChain`
     * `targetAddress` must implement the IWormholeReceiver interface
     * 
     * This function must be called with `msg.value` equal to `quoteEVMDeliveryPrice(targetChain, receiverValue, gasLimit)`
     * 
     * @param targetChain in Wormhole Chain ID format
     * @param targetAddress address to call on targetChain (that implements IWormholeReceiver) 
     * @param payload arbitrary bytes to pass in as parameter in call to `targetAddress`
     * @param receiverValue msg.value that delivery provider should pass in for call to `targetAddress` (in targetChain currency units)
     * @param gasLimit gas limit with which to call `targetAddress`. Any units of gas unused will be refunded according to the
     *        `targetChainRefundPerGasUnused` rate quoted by the delivery provider
     * @param refundChain The chain to deliver any refund to, in Wormhole Chain ID format
     * @param refundAddress The address on `refundChain` to deliver any refund to
     * @return sequence sequence number of published VAA containing delivery instructions
     */
    function sendPayloadToEvm(
        uint16 targetChain,
        address targetAddress,
        bytes memory payload,
        TargetNative receiverValue,
        Gas gasLimit,
        uint16 refundChain,
        address refundAddress
    ) external payable returns (uint64 sequence);

    /**
     * @notice Publishes an instruction for the default delivery provider
     * to relay a payload and VAAs specified by `vaaKeys` to the address `targetAddress` on chain `targetChain` 
     * with gas limit `gasLimit` and `msg.value` equal to `receiverValue`
     * 
     * `targetAddress` must implement the IWormholeReceiver interface
     * 
     * This function must be called with `msg.value` equal to `quoteEVMDeliveryPrice(targetChain, receiverValue, gasLimit)`
     * 
     * Any refunds (from leftover gas) will be paid to the delivery provider. In order to receive the refunds, use the `sendVaasToEvm` function 
     * with `refundChain` and `refundAddress` as parameters
     * 
     * @param targetChain in Wormhole Chain ID format
     * @param targetAddress address to call on targetChain (that implements IWormholeReceiver) 
     * @param payload arbitrary bytes to pass in as parameter in call to `targetAddress`
     * @param receiverValue msg.value that delivery provider should pass in for call to `targetAddress` (in targetChain currency units)
     * @param gasLimit gas limit with which to call `targetAddress`. 
     * @param vaaKeys Additional VAAs to pass in as parameter in call to `targetAddress`
     * @return sequence sequence number of published VAA containing delivery instructions
     */
    function sendVaasToEvm(
        uint16 targetChain,
        address targetAddress,
        bytes memory payload,
        TargetNative receiverValue,
        Gas gasLimit,
        VaaKey[] memory vaaKeys
    ) external payable returns (uint64 sequence);

    /**
     * @notice Publishes an instruction for the default delivery provider
     * to relay a payload and VAAs specified by `vaaKeys` to the address `targetAddress` on chain `targetChain` 
     * with gas limit `gasLimit` and `msg.value` equal to `receiverValue`
     * 
     * Any refunds (from leftover gas) will be sent to `refundAddress` on chain `refundChain`
     * `targetAddress` must implement the IWormholeReceiver interface
     * 
     * This function must be called with `msg.value` equal to `quoteEVMDeliveryPrice(targetChain, receiverValue, gasLimit)`
     * 
     * @param targetChain in Wormhole Chain ID format
     * @param targetAddress address to call on targetChain (that implements IWormholeReceiver) 
     * @param payload arbitrary bytes to pass in as parameter in call to `targetAddress`
     * @param receiverValue msg.value that delivery provider should pass in for call to `targetAddress` (in targetChain currency units)
     * @param gasLimit gas limit with which to call `targetAddress`. Any units of gas unused will be refunded according to the 
     *        `targetChainRefundPerGasUnused` rate quoted by the delivery provider
     * @param vaaKeys Additional VAAs to pass in as parameter in call to `targetAddress`
     * @param refundChain The chain to deliver any refund to, in Wormhole Chain ID format
     * @param refundAddress The address on `refundChain` to deliver any refund to
     * @return sequence sequence number of published VAA containing delivery instructions
     */
    function sendVaasToEvm(
        uint16 targetChain,
        address targetAddress,
        bytes memory payload,
        TargetNative receiverValue,
        Gas gasLimit,
        VaaKey[] memory vaaKeys,
        uint16 refundChain,
        address refundAddress
    ) external payable returns (uint64 sequence);

    /**
     * @notice Publishes an instruction for the delivery provider at `deliveryProviderAddress` 
     * to relay a payload and VAAs specified by `vaaKeys` to the address `targetAddress` on chain `targetChain` 
     * with gas limit `gasLimit` and `msg.value` equal to 
     * receiverValue + (arbitrary amount that is paid for by paymentForExtraReceiverValue of this chain's wei) in targetChain wei.
     * 
     * Any refunds (from leftover gas) will be sent to `refundAddress` on chain `refundChain`
     * `targetAddress` must implement the IWormholeReceiver interface
     * 
     * This function must be called with `msg.value` equal to 
     * quoteEVMDeliveryPrice(targetChain, receiverValue, gasLimit, deliveryProviderAddress) + paymentForExtraReceiverValue
     * 
     * @param targetChain in Wormhole Chain ID format
     * @param targetAddress address to call on targetChain (that implements IWormholeReceiver) 
     * @param payload arbitrary bytes to pass in as parameter in call to `targetAddress`
     * @param receiverValue msg.value that delivery provider should pass in for call to `targetAddress` (in targetChain currency units)
     * @param paymentForExtraReceiverValue amount (in current chain currency units) to spend on extra receiverValue 
     *        (in addition to the `receiverValue` specified)
     * @param gasLimit gas limit with which to call `targetAddress`. Any units of gas unused will be refunded according to the  
     *        `targetChainRefundPerGasUnused` rate quoted by the delivery provider
     * @param refundChain The chain to deliver any refund to, in Wormhole Chain ID format
     * @param refundAddress The address on `refundChain` to deliver any refund to
     * @param deliveryProviderAddress The address of the desired delivery provider's implementation of IDeliveryProvider
     * @param vaaKeys Additional VAAs to pass in as parameter in call to `targetAddress`
     * @param consistencyLevel Consistency level with which to publish the delivery instructions - see 
     *        https://book.wormhole.com/wormhole/3_coreLayerContracts.html?highlight=consistency#consistency-levels
     * @return sequence sequence number of published VAA containing delivery instructions
     */
    function sendToEvm(
        uint16 targetChain,
        address targetAddress,
        bytes memory payload,
        TargetNative receiverValue,
        LocalNative paymentForExtraReceiverValue,
        Gas gasLimit,
        uint16 refundChain,
        address refundAddress,
        address deliveryProviderAddress,
        VaaKey[] memory vaaKeys,
        uint8 consistencyLevel
    ) external payable returns (uint64 sequence);

    /**
     * @notice Publishes an instruction for the delivery provider at `deliveryProviderAddress` 
     * to relay a payload and external messages specified by `messageKeys` to the address `targetAddress` on chain `targetChain` 
     * with gas limit `gasLimit` and `msg.value` equal to 
     * receiverValue + (arbitrary amount that is paid for by paymentForExtraReceiverValue of this chain's wei) in targetChain wei.
     * 
     * Any refunds (from leftover gas) will be sent to `refundAddress` on chain `refundChain`
     * `targetAddress` must implement the IWormholeReceiver interface
     * 
     * This function must be called with `msg.value` equal to 
     * quoteEVMDeliveryPrice(targetChain, receiverValue, gasLimit, deliveryProviderAddress) + paymentForExtraReceiverValue
     *
     * Note: MessageKeys can specify wormhole messages (VaaKeys) or other types of messages (ex. USDC CCTP attestations). Ensure the selected 
     * DeliveryProvider supports all the MessageKey.keyType values specified or it will not be delivered!
     * 
     * @param targetChain in Wormhole Chain ID format
     * @param targetAddress address to call on targetChain (that implements IWormholeReceiver) 
     * @param payload arbitrary bytes to pass in as parameter in call to `targetAddress`
     * @param receiverValue msg.value that delivery provider should pass in for call to `targetAddress` (in targetChain currency units)
     * @param paymentForExtraReceiverValue amount (in current chain currency units) to spend on extra receiverValue 
     *        (in addition to the `receiverValue` specified)
     * @param gasLimit gas limit with which to call `targetAddress`. Any units of gas unused will be refunded according to the  
     *        `targetChainRefundPerGasUnused` rate quoted by the delivery provider
     * @param refundChain The chain to deliver any refund to, in Wormhole Chain ID format
     * @param refundAddress The address on `refundChain` to deliver any refund to
     * @param deliveryProviderAddress The address of the desired delivery provider's implementation of IDeliveryProvider
     * @param messageKeys Additional messagess to pass in as parameter in call to `targetAddress`
     * @param consistencyLevel Consistency level with which to publish the delivery instructions - see 
     *        https://book.wormhole.com/wormhole/3_coreLayerContracts.html?highlight=consistency#consistency-levels
     * @return sequence sequence number of published VAA containing delivery instructions
     */
    function sendToEvm(
        uint16 targetChain,
        address targetAddress,
        bytes memory payload,
        TargetNative receiverValue,
        LocalNative paymentForExtraReceiverValue,
        Gas gasLimit,
        uint16 refundChain,
        address refundAddress,
        address deliveryProviderAddress,
        MessageKey[] memory messageKeys,
        uint8 consistencyLevel
    ) external payable returns (uint64 sequence);
    
    /**
     * @notice Publishes an instruction for the delivery provider at `deliveryProviderAddress` 
     * to relay a payload and VAAs specified by `vaaKeys` to the address `targetAddress` on chain `targetChain` 
     * with `msg.value` equal to 
     * receiverValue + (arbitrary amount that is paid for by paymentForExtraReceiverValue of this chain's wei) in targetChain wei.
     * 
     * Any refunds (from leftover gas) will be sent to `refundAddress` on chain `refundChain`
     * `targetAddress` must implement the IWormholeReceiver interface
     * 
     * This function must be called with `msg.value` equal to 
     * quoteDeliveryPrice(targetChain, receiverValue, encodedExecutionParameters, deliveryProviderAddress) + paymentForExtraReceiverValue  
     * 
     * @param targetChain in Wormhole Chain ID format
     * @param targetAddress address to call on targetChain (that implements IWormholeReceiver), in Wormhole bytes32 format
     * @param payload arbitrary bytes to pass in as parameter in call to `targetAddress`
     * @param receiverValue msg.value that delivery provider should pass in for call to `targetAddress` (in targetChain currency units)
     * @param paymentForExtraReceiverValue amount (in current chain currency units) to spend on extra receiverValue 
     *        (in addition to the `receiverValue` specified)
     * @param encodedExecutionParameters encoded information on how to execute delivery that may impact pricing
     *        e.g. for version EVM_V1, this is a struct that encodes the `gasLimit` with which to call `targetAddress`
     * @param refundChain The chain to deliver any refund to, in Wormhole Chain ID format
     * @param refundAddress The address on `refundChain` to deliver any refund to, in Wormhole bytes32 format
     * @param deliveryProviderAddress The address of the desired delivery provider's implementation of IDeliveryProvider
     * @param vaaKeys Additional VAAs to pass in as parameter in call to `targetAddress`
     * @param consistencyLevel Consistency level with which to publish the delivery instructions - see 
     *        https://book.wormhole.com/wormhole/3_coreLayerContracts.html?highlight=consistency#consistency-levels
     * @return sequence sequence number of published VAA containing delivery instructions
     */
    function send(
        uint16 targetChain,
        bytes32 targetAddress,
        bytes memory payload,
        TargetNative receiverValue,
        LocalNative paymentForExtraReceiverValue,
        bytes memory encodedExecutionParameters,
        uint16 refundChain,
        bytes32 refundAddress,
        address deliveryProviderAddress,
        VaaKey[] memory vaaKeys,
        uint8 consistencyLevel
    ) external payable returns (uint64 sequence);

    /**
     * @notice Publishes an instruction for the delivery provider at `deliveryProviderAddress` 
     * to relay a payload and VAAs specified by `vaaKeys` to the address `targetAddress` on chain `targetChain` 
     * with `msg.value` equal to 
     * receiverValue + (arbitrary amount that is paid for by paymentForExtraReceiverValue of this chain's wei) in targetChain wei.
     * 
     * Any refunds (from leftover gas) will be sent to `refundAddress` on chain `refundChain`
     * `targetAddress` must implement the IWormholeReceiver interface
     * 
     * This function must be called with `msg.value` equal to 
     * quoteDeliveryPrice(targetChain, receiverValue, encodedExecutionParameters, deliveryProviderAddress) + paymentForExtraReceiverValue  
     *
     * Note: MessageKeys can specify wormhole messages (VaaKeys) or other types of messages (ex. USDC CCTP attestations). Ensure the selected 
     * DeliveryProvider supports all the MessageKey.keyType values specified or it will not be delivered!
     * 
     * @param targetChain in Wormhole Chain ID format
     * @param targetAddress address to call on targetChain (that implements IWormholeReceiver), in Wormhole bytes32 format
     * @param payload arbitrary bytes to pass in as parameter in call to `targetAddress`
     * @param receiverValue msg.value that delivery provider should pass in for call to `targetAddress` (in targetChain currency units)
     * @param paymentForExtraReceiverValue amount (in current chain currency units) to spend on extra receiverValue 
     *        (in addition to the `receiverValue` specified)
     * @param encodedExecutionParameters encoded information on how to execute delivery that may impact pricing
     *        e.g. for version EVM_V1, this is a struct that encodes the `gasLimit` with which to call `targetAddress`
     * @param refundChain The chain to deliver any refund to, in Wormhole Chain ID format
     * @param refundAddress The address on `refundChain` to deliver any refund to, in Wormhole bytes32 format
     * @param deliveryProviderAddress The address of the desired delivery provider's implementation of IDeliveryProvider
     * @param messageKeys Additional messagess to pass in as parameter in call to `targetAddress`
     * @param consistencyLevel Consistency level with which to publish the delivery instructions - see 
     *        https://book.wormhole.com/wormhole/3_coreLayerContracts.html?highlight=consistency#consistency-levels
     * @return sequence sequence number of published VAA containing delivery instructions
     */
    function send(
        uint16 targetChain,
        bytes32 targetAddress,
        bytes memory payload,
        TargetNative receiverValue,
        LocalNative paymentForExtraReceiverValue,
        bytes memory encodedExecutionParameters,
        uint16 refundChain,
        bytes32 refundAddress,
        address deliveryProviderAddress,
        MessageKey[] memory messageKeys,
        uint8 consistencyLevel
    ) external payable returns (uint64 sequence);

    /**
     * @notice Requests a previously published delivery instruction to be redelivered 
     * (e.g. with a different delivery provider)
     *
     * This function must be called with `msg.value` equal to 
     * quoteEVMDeliveryPrice(targetChain, newReceiverValue, newGasLimit, newDeliveryProviderAddress)
     * 
     *  @notice *** This will only be able to succeed if the following is true **
     *         - newGasLimit >= gas limit of the old instruction
     *         - newReceiverValue >= receiver value of the old instruction
     *         - newDeliveryProvider's `targetChainRefundPerGasUnused` >= old relay provider's `targetChainRefundPerGasUnused`
     * 
     * @param deliveryVaaKey VaaKey identifying the wormhole message containing the 
     *        previously published delivery instructions
     * @param targetChain The target chain that the original delivery targeted. Must match targetChain from original delivery instructions
     * @param newReceiverValue new msg.value that delivery provider should pass in for call to `targetAddress` (in targetChain currency units)
     * @param newGasLimit gas limit with which to call `targetAddress`. Any units of gas unused will be refunded according to the  
     *        `targetChainRefundPerGasUnused` rate quoted by the delivery provider, to the refund chain and address specified in the original request
     * @param newDeliveryProviderAddress The address of the desired delivery provider's implementation of IDeliveryProvider
     * @return sequence sequence number of published VAA containing redelivery instructions
     *
     * @notice *** This will only be able to succeed if the following is true **
     *         - newGasLimit >= gas limit of the old instruction
     *         - newReceiverValue >= receiver value of the old instruction
     */
    function resendToEvm(
        VaaKey memory deliveryVaaKey,
        uint16 targetChain,
        TargetNative newReceiverValue,
        Gas newGasLimit,
        address newDeliveryProviderAddress
    ) external payable returns (uint64 sequence);

    /**
     * @notice Requests a previously published delivery instruction to be redelivered 
     * 
     *
     * This function must be called with `msg.value` equal to 
     * quoteDeliveryPrice(targetChain, newReceiverValue, newEncodedExecutionParameters, newDeliveryProviderAddress)
     * 
     * @param deliveryVaaKey VaaKey identifying the wormhole message containing the 
     *        previously published delivery instructions
     * @param targetChain The target chain that the original delivery targeted. Must match targetChain from original delivery instructions
     * @param newReceiverValue new msg.value that delivery provider should pass in for call to `targetAddress` (in targetChain currency units)
     * @param newEncodedExecutionParameters new encoded information on how to execute delivery that may impact pricing
     *        e.g. for version EVM_V1, this is a struct that encodes the `gasLimit` with which to call `targetAddress`
     * @param newDeliveryProviderAddress The address of the desired delivery provider's implementation of IDeliveryProvider
     * @return sequence sequence number of published VAA containing redelivery instructions
     * 
     *  @notice *** This will only be able to succeed if the following is true **
     *         - (For EVM_V1) newGasLimit >= gas limit of the old instruction
     *         - newReceiverValue >= receiver value of the old instruction
     *         - (For EVM_V1) newDeliveryProvider's `targetChainRefundPerGasUnused` >= old relay provider's `targetChainRefundPerGasUnused`
     */
    function resend(
        VaaKey memory deliveryVaaKey,
        uint16 targetChain,
        TargetNative newReceiverValue,
        bytes memory newEncodedExecutionParameters,
        address newDeliveryProviderAddress
    ) external payable returns (uint64 sequence);

    /**
     * @notice Returns the price to request a relay to chain `targetChain`, using the default delivery provider
     * 
     * @param targetChain in Wormhole Chain ID format
     * @param receiverValue msg.value that delivery provider should pass in for call to `targetAddress` (in targetChain currency units)
     * @param gasLimit gas limit with which to call `targetAddress`. 
     * @return nativePriceQuote Price, in units of current chain currency, that the delivery provider charges to perform the relay
     * @return targetChainRefundPerGasUnused amount of target chain currency that will be refunded per unit of gas unused, 
     *         if a refundAddress is specified. 
     *         Note: This value can be overridden by the delivery provider on the target chain. The returned value here should be considered to be a 
     *         promise by the delivery provider of the amount of refund per gas unused that will be returned to the refundAddress at the target chain. 
     *         If a delivery provider decides to override, this will be visible as part of the emitted Delivery event on the target chain. 
     */
    function quoteEVMDeliveryPrice(
        uint16 targetChain,
        TargetNative receiverValue,
        Gas gasLimit
    ) external view returns (LocalNative nativePriceQuote, GasPrice targetChainRefundPerGasUnused);

    /**
     * @notice Returns the price to request a relay to chain `targetChain`, using delivery provider `deliveryProviderAddress`
     * 
     * @param targetChain in Wormhole Chain ID format
     * @param receiverValue msg.value that delivery provider should pass in for call to `targetAddress` (in targetChain currency units)
     * @param gasLimit gas limit with which to call `targetAddress`. 
     * @param deliveryProviderAddress The address of the desired delivery provider's implementation of IDeliveryProvider
     * @return nativePriceQuote Price, in units of current chain currency, that the delivery provider charges to perform the relay
     * @return targetChainRefundPerGasUnused amount of target chain currency that will be refunded per unit of gas unused, 
     *         if a refundAddress is specified
     *         Note: This value can be overridden by the delivery provider on the target chain. The returned value here should be considered to be a 
     *         promise by the delivery provider of the amount of refund per gas unused that will be returned to the refundAddress at the target chain. 
     *         If a delivery provider decides to override, this will be visible as part of the emitted Delivery event on the target chain.
     */
    function quoteEVMDeliveryPrice(
        uint16 targetChain,
        TargetNative receiverValue,
        Gas gasLimit,
        address deliveryProviderAddress
    ) external view returns (LocalNative nativePriceQuote, GasPrice targetChainRefundPerGasUnused);

    /**
     * @notice Returns the price to request a relay to chain `targetChain`, using delivery provider `deliveryProviderAddress`
     * 
     * @param targetChain in Wormhole Chain ID format
     * @param receiverValue msg.value that delivery provider should pass in for call to `targetAddress` (in targetChain currency units)
     * @param encodedExecutionParameters encoded information on how to execute delivery that may impact pricing
     *        e.g. for version EVM_V1, this is a struct that encodes the `gasLimit` with which to call `targetAddress`
     * @param deliveryProviderAddress The address of the desired delivery provider's implementation of IDeliveryProvider
     * @return nativePriceQuote Price, in units of current chain currency, that the delivery provider charges to perform the relay
     * @return encodedExecutionInfo encoded information on how the delivery will be executed
     *        e.g. for version EVM_V1, this is a struct that encodes the `gasLimit` and `targetChainRefundPerGasUnused`
     *             (which is the amount of target chain currency that will be refunded per unit of gas unused, 
     *              if a refundAddress is specified)
     */
    function quoteDeliveryPrice(
        uint16 targetChain,
        TargetNative receiverValue,
        bytes memory encodedExecutionParameters,
        address deliveryProviderAddress
    ) external view returns (LocalNative nativePriceQuote, bytes memory encodedExecutionInfo);

    /**
     * @notice Returns the (extra) amount of target chain currency that `targetAddress`
     * will be called with, if the `paymentForExtraReceiverValue` field is set to `currentChainAmount`
     * 
     * @param targetChain in Wormhole Chain ID format
     * @param currentChainAmount The value that `paymentForExtraReceiverValue` will be set to
     * @param deliveryProviderAddress The address of the desired delivery provider's implementation of IDeliveryProvider
     * @return targetChainAmount The amount such that if `targetAddress` will be called with `msg.value` equal to
     *         receiverValue + targetChainAmount
     */
    function quoteNativeForChain(
        uint16 targetChain,
        LocalNative currentChainAmount,
        address deliveryProviderAddress
    ) external view returns (TargetNative targetChainAmount);

    /**
     * @notice Returns the address of the current default delivery provider
     * @return deliveryProvider The address of (the default delivery provider)'s contract on this source
     *   chain. This must be a contract that implements IDeliveryProvider.
     */
    function getDefaultDeliveryProvider() external view returns (address deliveryProvider);
}

/**
 * @title IWormholeRelayerDelivery
 * @notice The interface to execute deliveries. Only relevant for Delivery Providers 
 */
interface IWormholeRelayerDelivery is IWormholeRelayerBase {
    enum DeliveryStatus {
        SUCCESS,
        RECEIVER_FAILURE
    }

    enum RefundStatus {
        REFUND_SENT,
        REFUND_FAIL,
        CROSS_CHAIN_REFUND_SENT,
        CROSS_CHAIN_REFUND_FAIL_PROVIDER_NOT_SUPPORTED,
        CROSS_CHAIN_REFUND_FAIL_NOT_ENOUGH,
        NO_REFUND_REQUESTED
    }

    /**
     * @custom:member recipientContract - The target contract address
     * @custom:member sourceChain - The chain which this delivery was requested from (in wormhole
     *     ChainID format)
     * @custom:member sequence - The wormhole sequence number of the delivery VAA on the source chain
     *     corresponding to this delivery request
     * @custom:member deliveryVaaHash - The hash of the delivery VAA corresponding to this delivery
     *     request
     * @custom:member gasUsed - The amount of gas that was used to call your target contract 
     * @custom:member status:
     *   - RECEIVER_FAILURE, if the target contract reverts
     *   - SUCCESS, if the target contract doesn't revert
     * @custom:member additionalStatusInfo:
     *   - If status is SUCCESS, then this is empty.
     *   - If status is RECEIVER_FAILURE, this is `RETURNDATA_TRUNCATION_THRESHOLD` bytes of the
     *       return data (i.e. potentially truncated revert reason information).
     * @custom:member refundStatus - Result of the refund. REFUND_SUCCESS or REFUND_FAIL are for
     *     refunds where targetChain=refundChain; the others are for targetChain!=refundChain,
     *     where a cross chain refund is necessary, or if the default code path is used where no refund is requested (NO_REFUND_REQUESTED)
     * @custom:member overridesInfo:
     *   - If not an override: empty bytes array
     *   - Otherwise: An encoded `DeliveryOverride`
     */
    event Delivery(
        address indexed recipientContract,
        uint16 indexed sourceChain,
        uint64 indexed sequence,
        bytes32 deliveryVaaHash,
        DeliveryStatus status,
        Gas gasUsed,
        RefundStatus refundStatus,
        bytes additionalStatusInfo,
        bytes overridesInfo
    );

    /**
     * @notice The delivery provider calls `deliver` to relay messages as described by one delivery instruction
     * 
     * The delivery provider must pass in the specified (by VaaKeys[]) signed wormhole messages (VAAs) from the source chain
     * as well as the signed wormhole message with the delivery instructions (the delivery VAA)
     *
     * The messages will be relayed to the target address (with the specified gas limit and receiver value) iff the following checks are met:
     * - the delivery VAA has a valid signature
     * - the delivery VAA's emitter is one of these WormholeRelayer contracts
     * - the delivery provider passed in at least enough of this chain's currency as msg.value (enough meaning the maximum possible refund)     
     * - the instruction's target chain is this chain
     * - the relayed signed VAAs match the descriptions in container.messages (the VAA hashes match, or the emitter address, sequence number pair matches, depending on the description given)
     *
     * @param encodedVMs - An array of signed wormhole messages (all from the same source chain
     *     transaction)
     * @param encodedDeliveryVAA - Signed wormhole message from the source chain's WormholeRelayer
     *     contract with payload being the encoded delivery instruction container
     * @param relayerRefundAddress - The address to which any refunds to the delivery provider
     *     should be sent
     * @param deliveryOverrides - Optional overrides field which must be either an empty bytes array or
     *     an encoded DeliveryOverride struct
     */
    function deliver(
        bytes[] memory encodedVMs,
        bytes memory encodedDeliveryVAA,
        address payable relayerRefundAddress,
        bytes memory deliveryOverrides
    ) external payable;
}

interface IWormholeRelayer is IWormholeRelayerDelivery, IWormholeRelayerSend {}

/*
 *  Errors thrown by IWormholeRelayer contract
 */

// Bound chosen by the following formula: `memoryWord * 4 + selectorSize`.
// This means that an error identifier plus four fixed size arguments should be available to developers.
// In the case of a `require` revert with error message, this should provide 2 memory word's worth of data.
uint256 constant RETURNDATA_TRUNCATION_THRESHOLD = 132;

//When msg.value was not equal to `delivery provider's quoted delivery price` + `paymentForExtraReceiverValue`
error InvalidMsgValue(LocalNative msgValue, LocalNative totalFee);

error RequestedGasLimitTooLow();

error DeliveryProviderDoesNotSupportTargetChain(address relayer, uint16 chainId);
error DeliveryProviderCannotReceivePayment();
error DeliveryProviderDoesNotSupportMessageKeyType(uint8 keyType);

//When calling `delivery()` a second time even though a delivery is already in progress
error ReentrantDelivery(address msgSender, address lockedBy);

error InvalidPayloadId(uint8 parsed, uint8 expected);
error InvalidPayloadLength(uint256 received, uint256 expected);
error InvalidVaaKeyType(uint8 parsed);
error TooManyMessageKeys(uint256 numMessageKeys);

error InvalidDeliveryVaa(string reason);
//When the delivery VAA (signed wormhole message with delivery instructions) was not emitted by the
//  registered WormholeRelayer contract
error InvalidEmitter(bytes32 emitter, bytes32 registered, uint16 chainId);
error MessageKeysLengthDoesNotMatchMessagesLength(uint256 keys, uint256 vaas);
error VaaKeysDoNotMatchVaas(uint8 index);
//When someone tries to call an external function of the WormholeRelayer that is only intended to be
//  called by the WormholeRelayer itself (to allow retroactive reverts for atomicity)
error RequesterNotWormholeRelayer();

//When trying to relay a `DeliveryInstruction` to any other chain but the one it was specified for
error TargetChainIsNotThisChain(uint16 targetChain);
//When a `DeliveryOverride` contains a gas limit that's less than the original
error InvalidOverrideGasLimit();
//When a `DeliveryOverride` contains a receiver value that's less than the original
error InvalidOverrideReceiverValue();
//When a `DeliveryOverride` contains a 'refund per unit of gas unused' that's less than the original
error InvalidOverrideRefundPerGasUnused();

//When the delivery provider doesn't pass in sufficient funds (i.e. msg.value does not cover the
// maximum possible refund to the user)
error InsufficientRelayerFunds(LocalNative msgValue, LocalNative minimum);

// -------------------------------------- Persistent Storage ---------------------------------------

//We have to hardcode the keccak256 values by hand rather than having them calculated because:
//  solc: TypeError: Only direct number constants and references to such constants are supported by
//          inline assembly.
//And presumably what they mean by "direct number constants" is number literals...

struct GovernanceState {
    // mapping of IWormhole.VM.hash of previously executed governance VMs
    mapping(bytes32 => bool) consumedGovernanceActions;
}

//keccak256("GovernanceState") - 1
bytes32 constant GOVERNANCE_STORAGE_SLOT =
    0x970ad24d4754c92e299cabb86552091f5df0a15abc0f1b71f37d3e30031585dc;

function getGovernanceState() pure returns (GovernanceState storage state) {
    assembly ("memory-safe") {
        state.slot := GOVERNANCE_STORAGE_SLOT
    }
}

struct DefaultDeliveryProviderState {
    // address of the default relay provider on this chain
    address defaultDeliveryProvider;
}

//keccak256("DefaultRelayProviderState") - 1
bytes32 constant DEFAULT_RELAY_PROVIDER_STORAGE_SLOT =
    0xebc28a1927f62765bfb7ada566eeab2d31a98c65dbd1e8cad64acae2a3ae45d4;

function getDefaultDeliveryProviderState()
    pure
    returns (DefaultDeliveryProviderState storage state)
{
    assembly ("memory-safe") {
        state.slot := DEFAULT_RELAY_PROVIDER_STORAGE_SLOT
    }
}

struct RegisteredWormholeRelayersState {
    // chainId => wormhole address mapping of relayer contracts on other chains
    mapping(uint16 => bytes32) registeredWormholeRelayers;
}

//keccak256("RegisteredCoreRelayersState") - 1
bytes32 constant REGISTERED_CORE_RELAYERS_STORAGE_SLOT =
    0x9e4e57806ba004485cfae8ca22fb13380f01c10b1b0ccf48c20464961643cf6d;

function getRegisteredWormholeRelayersState()
    pure
    returns (RegisteredWormholeRelayersState storage state)
{
    assembly ("memory-safe") {
        state.slot := REGISTERED_CORE_RELAYERS_STORAGE_SLOT
    }
}

// Replay Protection and Indexing

struct DeliverySuccessState {
    mapping(bytes32 => uint256) deliverySuccessBlock;
}

struct DeliveryFailureState {
    mapping(bytes32 => uint256) deliveryFailureBlock;
}

//keccak256("DeliverySuccessState") - 1
bytes32 constant DELIVERY_SUCCESS_STATE_STORAGE_SLOT =
    0x1b988580e74603c035f5a7f71f2ae4647578af97cd0657db620836b9955fd8f5;

//keccak256("DeliveryFailureState") - 1
bytes32 constant DELIVERY_FAILURE_STATE_STORAGE_SLOT =
    0x6c615753402911c4de18a758def0565f37c41834d6eff72b16cb37cfb697f2a5;

function getDeliverySuccessState() pure returns (DeliverySuccessState storage state) {
    assembly ("memory-safe") {
        state.slot := DELIVERY_SUCCESS_STATE_STORAGE_SLOT
    }
}

function getDeliveryFailureState() pure returns (DeliveryFailureState storage state) {
    assembly ("memory-safe") {
        state.slot := DELIVERY_FAILURE_STATE_STORAGE_SLOT
    }
}

struct ReentrancyGuardState {
    // if 0 address, no reentrancy guard is active
    // otherwise, the address of the contract that has locked the reentrancy guard (msg.sender)
    address lockedBy;
}

//keccak256("ReentrancyGuardState") - 1
bytes32 constant REENTRANCY_GUARD_STORAGE_SLOT =
    0x44dc27ebd67a87ad2af1d98fc4a5f971d9492fe12498e4c413ab5a05b7807a67;

function getReentrancyGuardState() pure returns (ReentrancyGuardState storage state) {
    assembly ("memory-safe") {
        state.slot := REENTRANCY_GUARD_STORAGE_SLOT
    }
}

struct DeliveryTmpState {
    // the refund chain for the in-progress delivery
    uint16 refundChain;
    // the refund address for the in-progress delivery
    bytes32 refundAddress;
}

//keccak256("DeliveryTmpState") - 1
bytes32 constant DELIVERY_TMP_STORAGE_SLOT =
    0x1a2a8eb52f1d00a1242a3f8cc031e30a32870ff64f69009c4e06f75bd842fd22;

function getDeliveryTmpState() pure returns (DeliveryTmpState storage state) {
    assembly ("memory-safe") {
        state.slot := DELIVERY_TMP_STORAGE_SLOT
    }
}


abstract contract WormholeRelayerBase is IWormholeRelayerBase {
    using WeiLib for Wei;
    using GasLib for Gas;
    using WeiPriceLib for WeiPrice;
    using GasPriceLib for GasPrice;
    using LocalNativeLib for LocalNative;

    //see https://book.wormhole.com/wormhole/3_coreLayerContracts.html#consistency-levels
    //  15 is valid choice for now but ultimately we want something more canonical (202?)
    //  Also, these values should definitely not be defined here but should be provided by IWormhole!
    uint8 internal constant CONSISTENCY_LEVEL_FINALIZED = 15;
    uint8 internal constant CONSISTENCY_LEVEL_INSTANT = 200;

    IWormhole private immutable wormhole_;
    uint16 private immutable chainId_;

    constructor(address _wormhole) {
        wormhole_ = IWormhole(_wormhole);
        chainId_ = uint16(wormhole_.chainId());
    }

    function getRegisteredWormholeRelayerContract(uint16 chainId) public view returns (bytes32) {
        return getRegisteredWormholeRelayersState().registeredWormholeRelayers[chainId];
    }

    function deliveryAttempted(bytes32 deliveryHash) public view returns (bool attempted) {
        return getDeliverySuccessState().deliverySuccessBlock[deliveryHash] != 0 ||
            getDeliveryFailureState().deliveryFailureBlock[deliveryHash] != 0;
    }

    function deliverySuccessBlock(bytes32 deliveryHash) public view returns (uint256 blockNumber) {
        return getDeliverySuccessState().deliverySuccessBlock[deliveryHash];
    }

    function deliveryFailureBlock(bytes32 deliveryHash) public view returns (uint256 blockNumber) {
        return getDeliveryFailureState().deliveryFailureBlock[deliveryHash];
    }

    //Our get functions require view instead of pure (despite not actually reading storage) because
    //  they can't be evaluated at compile time. (https://ethereum.stackexchange.com/a/120630/103366)

    function getWormhole() internal view returns (IWormhole) {
        return wormhole_;
    }

    function getChainId() internal view returns (uint16) {
        return chainId_;
    }

    function getWormholeMessageFee() internal view returns (LocalNative) {
        return LocalNative.wrap(getWormhole().messageFee());
    }

    function msgValue() internal view returns (LocalNative) {
        return LocalNative.wrap(msg.value);
    }

    function checkMsgValue(
        LocalNative wormholeMessageFee,
        LocalNative deliveryPrice,
        LocalNative paymentForExtraReceiverValue
    ) internal view {
        if (msgValue() != deliveryPrice + paymentForExtraReceiverValue + wormholeMessageFee) {
            revert InvalidMsgValue(
                msgValue(), deliveryPrice + paymentForExtraReceiverValue + wormholeMessageFee
            );
        }
    }

    function publishAndPay(
        LocalNative wormholeMessageFee,
        LocalNative deliveryQuote,
        LocalNative paymentForExtraReceiverValue,
        bytes memory encodedInstruction,
        uint8 consistencyLevel,
        address payable rewardAddress
    ) internal returns (uint64 sequence, bool paymentSucceeded) {
        sequence = getWormhole().publishMessage{value: wormholeMessageFee.unwrap()}(
            0, encodedInstruction, consistencyLevel
        );

        paymentSucceeded = pay(
            rewardAddress,
            deliveryQuote + paymentForExtraReceiverValue
        );

        emit SendEvent(sequence, deliveryQuote, paymentForExtraReceiverValue);
    }

    modifier nonReentrant() {
        // Reentrancy guard
        if (getReentrancyGuardState().lockedBy != address(0)) {
            revert ReentrantDelivery(msg.sender, getReentrancyGuardState().lockedBy);
        }
        getReentrancyGuardState().lockedBy = msg.sender;

        _;

        getReentrancyGuardState().lockedBy = address(0);
    }

     // ----------------------- delivery transaction temorary storage functions -----------------------

    function recordRefundInformation(uint16 refundChain, bytes32 refundAddress) internal {
        DeliveryTmpState storage state = getDeliveryTmpState();
        state.refundChain = refundChain;
        state.refundAddress = refundAddress;
    }

    function clearRefundInformation() internal {
        DeliveryTmpState storage state = getDeliveryTmpState();
        state.refundChain = 0;
        state.refundAddress = bytes32(0);
    }

    function getCurrentRefundChain() internal view returns (uint16) {
        return getDeliveryTmpState().refundChain;
    }

    function getCurrentRefundAddress() internal view returns (bytes32) {
        return getDeliveryTmpState().refundAddress;
    }
}

error GovernanceActionAlreadyConsumed(bytes32 hash);
error InvalidGovernanceVM(string reason);
error InvalidGovernanceChainId(uint16 parsed, uint16 expected);
error InvalidGovernanceContract(bytes32 parsed, bytes32 expected);

error InvalidPayloadChainId(uint16 parsed, uint16 expected);
error InvalidPayloadAction(uint8 parsed, uint8 expected);
error InvalidPayloadModule(bytes32 parsed, bytes32 expected);
error InvalidFork();
error ContractUpgradeFailed(bytes failure);
error ChainAlreadyRegistered(uint16 chainId, bytes32 registeredWormholeRelayerContract);
error InvalidDefaultDeliveryProvider(bytes32 defaultDeliveryProvider);

abstract contract WormholeRelayerGovernance is WormholeRelayerBase, ERC1967Upgrade {
    //This constant should actually be defined in IWormhole. Alas, it isn't.
    uint16 private constant WORMHOLE_CHAINID_UNSET = 0;

    /**
     * Governance VMs are encoded in a packed fashion using the general wormhole scheme:
     *   GovernancePacket = <Common Header|Action Parameters>
     *
     * For a more detailed explanation see here:
     *   - https://docs.wormhole.com/wormhole/governance
     *   - https://github.com/wormhole-foundation/wormhole/blob/main/whitepapers/0002_governance_messaging.md
     */

    //Right shifted ascii encoding of "WormholeRelayer"
    bytes32 private constant module =
        0x0000000000000000000000000000000000576f726d686f6c6552656c61796572;

    /**
     * The choice of action enumeration and parameters follows the scheme of the core bridge:
     *   - https://github.com/wormhole-foundation/wormhole/blob/main/ethereum/contracts/bridge/BridgeGovernance.sol#L115
     */

    /**
     * Registers a wormhole relayer contract that was deployed on another chain with the WormholeRelayer on
     *   this chain. The equivalent to the core bridge's registerChain action.
     *
     * Action Parameters:
     *   - uint16 foreignChainId
     *   - bytes32 foreignContractAddress
     */
    uint8 private constant GOVERNANCE_ACTION_REGISTER_WORMHOLE_RELAYER_CONTRACT = 1;

    /**
     * Upgrades the WormholeRelayer contract to a new implementation. The equivalent to the core bridge's
     *   upgrade action.
     *
     * Action Parameters:
     *   - bytes32 newImplementation
     */
    uint8 private constant GOVERNANCE_ACTION_CONTRACT_UPGRADE = 2;

    /**
     * Sets the default relay provider for the WormholeRelayer. Has no equivalent in the core bridge.
     *
     * Action Parameters:
     *   - bytes32 newProvider
     */
    uint8 private constant GOVERNANCE_ACTION_UPDATE_DEFAULT_PROVIDER = 3;

    //By checking that only the contract can call itself, we can enforce that the migration code is
    //  executed upon program upgrade and that it can't be called externally by anyone else.
    function checkAndExecuteUpgradeMigration() external {
        assert(msg.sender == address(this));
        executeUpgradeMigration();
    }

    function executeUpgradeMigration() internal virtual {
        //override and implement in WormholeRelayer upon contract upgrade (if required)
    }

    function registerWormholeRelayerContract(bytes memory encodedVm) external {
        (uint16 foreignChainId, bytes32 foreignAddress) =
            parseAndCheckRegisterWormholeRelayerContractVm(encodedVm);

        getRegisteredWormholeRelayersState().registeredWormholeRelayers[foreignChainId] =
            foreignAddress;
    }

    event ContractUpgraded(address indexed oldContract, address indexed newContract);

    function submitContractUpgrade(bytes memory encodedVm) external {
        address currentImplementation = _getImplementation();
        address newImplementation = parseAndCheckContractUpgradeVm(encodedVm);

        _upgradeTo(newImplementation);

        (bool success, bytes memory revertData) =
            address(this).call(abi.encodeCall(this.checkAndExecuteUpgradeMigration, ()));

        if (!success) {
            revert ContractUpgradeFailed(revertData);
        }

        emit ContractUpgraded(currentImplementation, newImplementation);
    }

    function setDefaultDeliveryProvider(bytes memory encodedVm) external {
        address newProvider = parseAndCheckRegisterDefaultDeliveryProviderVm(encodedVm);

        getDefaultDeliveryProviderState().defaultDeliveryProvider = newProvider;
    }

    // ------------------------------------------- PRIVATE -------------------------------------------
    using BytesParsing for bytes;

    function parseAndCheckRegisterWormholeRelayerContractVm(bytes memory encodedVm)
        private
        returns (uint16 foreignChainId, bytes32 foreignAddress)
    {
        bytes memory payload = verifyAndConsumeGovernanceVM(encodedVm);
        uint256 offset = parseAndCheckPayloadHeader(
            payload, GOVERNANCE_ACTION_REGISTER_WORMHOLE_RELAYER_CONTRACT, true
        );

        (foreignChainId, offset) = payload.asUint16Unchecked(offset);
        (foreignAddress, offset) = payload.asBytes32Unchecked(offset);

        checkLength(payload, offset);

        if (getRegisteredWormholeRelayerContract(foreignChainId) != bytes32(0)) {
            revert ChainAlreadyRegistered(
                foreignChainId, getRegisteredWormholeRelayerContract(foreignChainId)
            );
        }
    }

    function parseAndCheckContractUpgradeVm(bytes memory encodedVm)
        private
        returns (address newImplementation)
    {
        bytes memory payload = verifyAndConsumeGovernanceVM(encodedVm);
        uint256 offset =
            parseAndCheckPayloadHeader(payload, GOVERNANCE_ACTION_CONTRACT_UPGRADE, false);

        bytes32 newImplementationWhFmt;
        (newImplementationWhFmt, offset) = payload.asBytes32Unchecked(offset);
        //fromWormholeFormat reverts if first 12 bytes aren't zero (i.e. if it's not an EVM address)
        newImplementation = fromWormholeFormat(newImplementationWhFmt);

        checkLength(payload, offset);
    }

    function parseAndCheckRegisterDefaultDeliveryProviderVm(bytes memory encodedVm)
        private
        returns (address newProvider)
    {
        bytes memory payload = verifyAndConsumeGovernanceVM(encodedVm);
        uint256 offset =
            parseAndCheckPayloadHeader(payload, GOVERNANCE_ACTION_UPDATE_DEFAULT_PROVIDER, false);

        bytes32 newProviderWhFmt;
        (newProviderWhFmt, offset) = payload.asBytes32Unchecked(offset);
        //fromWormholeFormat reverts if first 12 bytes aren't zero (i.e. if it's not an EVM address)
        newProvider = fromWormholeFormat(newProviderWhFmt);

        checkLength(payload, offset);

        if (newProvider == address(0)) {
            revert InvalidDefaultDeliveryProvider(newProviderWhFmt);
        }
    }

    function verifyAndConsumeGovernanceVM(bytes memory encodedVm)
        private
        returns (bytes memory payload)
    {
        (IWormhole.VM memory vm, bool valid, string memory reason) =
            getWormhole().parseAndVerifyVM(encodedVm);

        if (!valid) {
            revert InvalidGovernanceVM(reason);
        }

        uint16 governanceChainId = getWormhole().governanceChainId();
        if (vm.emitterChainId != governanceChainId) {
            revert InvalidGovernanceChainId(vm.emitterChainId, governanceChainId);
        }

        bytes32 governanceContract = getWormhole().governanceContract();
        if (vm.emitterAddress != governanceContract) {
            revert InvalidGovernanceContract(vm.emitterAddress, governanceContract);
        }

        bool consumed = getGovernanceState().consumedGovernanceActions[vm.hash];
        if (consumed) {
            revert GovernanceActionAlreadyConsumed(vm.hash);
        }

        getGovernanceState().consumedGovernanceActions[vm.hash] = true;

        return vm.payload;
    }

    function parseAndCheckPayloadHeader(
        bytes memory encodedPayload,
        uint8 expectedAction,
        bool allowUnset
    ) private view returns (uint256 offset) {
        bytes32 parsedModule;
        (parsedModule, offset) = encodedPayload.asBytes32Unchecked(offset);
        if (parsedModule != module) {
            revert InvalidPayloadModule(parsedModule, module);
        }

        uint8 parsedAction;
        (parsedAction, offset) = encodedPayload.asUint8Unchecked(offset);
        if (parsedAction != expectedAction) {
            revert InvalidPayloadAction(parsedAction, expectedAction);
        }

        uint16 parsedChainId;
        (parsedChainId, offset) = encodedPayload.asUint16Unchecked(offset);
        if (!(parsedChainId == WORMHOLE_CHAINID_UNSET && allowUnset)) {
            if (getWormhole().isFork()) {
                revert InvalidFork();
            }

            if (parsedChainId != getChainId()) {
                revert InvalidPayloadChainId(parsedChainId, getChainId());
            }
        }
    }

    function checkLength(bytes memory payload, uint256 expected) private pure {
        if (payload.length != expected) {
            revert InvalidPayloadLength(payload.length, expected);
        }
    }
}

struct DeliveryInstruction {
    uint16 targetChain;
    bytes32 targetAddress;
    bytes payload;
    TargetNative requestedReceiverValue;
    TargetNative extraReceiverValue;
    bytes encodedExecutionInfo;
    uint16 refundChain;
    bytes32 refundAddress;
    bytes32 refundDeliveryProvider;
    bytes32 sourceDeliveryProvider;
    bytes32 senderAddress;
    MessageKey[] messageKeys;
}

// Meant to hold all necessary values for `CoreRelayerDelivery::executeInstruction`
// Nothing more and nothing less.
struct EvmDeliveryInstruction {
  uint16 sourceChain;
  bytes32 targetAddress;
  bytes payload;
  Gas gasLimit;
  TargetNative totalReceiverValue;
  GasPrice targetChainRefundPerGasUnused;
  bytes32 senderAddress;
  bytes32 deliveryHash;
  bytes[] signedVaas;
}

struct RedeliveryInstruction {
    VaaKey deliveryVaaKey;
    uint16 targetChain;
    TargetNative newRequestedReceiverValue;
    bytes newEncodedExecutionInfo;
    bytes32 newSourceDeliveryProvider;
    bytes32 newSenderAddress;
}

/**
 * @notice When a user requests a `resend()`, a `RedeliveryInstruction` is emitted by the
 *     WormholeRelayer and in turn converted by the relay provider into an encoded (=serialized)
 *     `DeliveryOverride` struct which is then passed to `delivery()` to override the parameters of
 *     a previously failed delivery attempt.
 *
 * @custom:member newReceiverValue - must >= than the `receiverValue` specified in the original
 *     `DeliveryInstruction`
 * @custom:member newExecutionInfo - for EVM_V1, must contain a gasLimit and targetChainRefundPerGasUnused
 * such that 
 * - gasLimit is >= the `gasLimit` specified in the `executionParameters`
 *     of the original `DeliveryInstruction`
 * - targetChainRefundPerGasUnused is >=  the `targetChainRefundPerGasUnused` specified in the original
 *     `DeliveryInstruction`
 * @custom:member redeliveryHash - the hash of the redelivery which is being performed
 */
struct DeliveryOverride {
    TargetNative newReceiverValue;
    bytes newExecutionInfo;
    bytes32 redeliveryHash;
}

library WormholeRelayerSerde {
    using BytesParsing for bytes;
    using WeiLib for Wei;
    using GasLib for Gas;

    //The slightly subtle difference between `PAYLOAD_ID`s and `VERSION`s is that payload ids carry
    //  both type information _and_ version information, while `VERSION`s only carry the latter.
    //That is, when deserialing a "version struct" we already know the expected type, but since we
    //  publish both Delivery _and_ Redelivery instructions as serialized messages, we need a robust
    //  way to distinguish both their type and their version during deserialization.
    uint8 private constant VERSION_VAAKEY = 1;
    uint8 private constant VERSION_DELIVERY_OVERRIDE = 1;
    uint8 private constant PAYLOAD_ID_DELIVERY_INSTRUCTION = 1;
    uint8 private constant PAYLOAD_ID_REDELIVERY_INSTRUCTION = 2;

    uint256 constant VAA_KEY_TYPE_LENGTH = 2 + 32 + 8;

    // ---------------------- "public" (i.e implicitly internal) encode/decode -----------------------

    //TODO GAS OPTIMIZATION: All the recursive abi.encodePacked calls in here are _insanely_ gas
    //    inefficient (unless the optimizer is smart enough to just concatenate them tail-recursion
    //    style which seems highly unlikely)

    function encode(DeliveryInstruction memory strct)
        internal
        pure
        returns (bytes memory encoded)
    {
        encoded = abi.encodePacked(
            PAYLOAD_ID_DELIVERY_INSTRUCTION,
            strct.targetChain,
            strct.targetAddress,
            encodeBytes(strct.payload),
            strct.requestedReceiverValue,
            strct.extraReceiverValue
        );
        encoded = abi.encodePacked(
            encoded,
            encodeBytes(strct.encodedExecutionInfo),
            strct.refundChain,
            strct.refundAddress,
            strct.refundDeliveryProvider,
            strct.sourceDeliveryProvider,
            strct.senderAddress,
            encodeMessageKeyArray(strct.messageKeys)
        );
    }

    function decodeDeliveryInstruction(bytes memory encoded)
        internal
        pure
        returns (DeliveryInstruction memory strct)
    {
        uint256 offset = checkUint8(encoded, 0, PAYLOAD_ID_DELIVERY_INSTRUCTION);

        uint256 requestedReceiverValue;
        uint256 extraReceiverValue;

        (strct.targetChain, offset) = encoded.asUint16Unchecked(offset);
        (strct.targetAddress, offset) = encoded.asBytes32Unchecked(offset);
        (strct.payload, offset) = decodeBytes(encoded, offset);
        (requestedReceiverValue, offset) = encoded.asUint256Unchecked(offset);
        (extraReceiverValue, offset) = encoded.asUint256Unchecked(offset);
        (strct.encodedExecutionInfo, offset) = decodeBytes(encoded, offset);
        (strct.refundChain, offset) = encoded.asUint16Unchecked(offset);
        (strct.refundAddress, offset) = encoded.asBytes32Unchecked(offset);
        (strct.refundDeliveryProvider, offset) = encoded.asBytes32Unchecked(offset);
        (strct.sourceDeliveryProvider, offset) = encoded.asBytes32Unchecked(offset);
        (strct.senderAddress, offset) = encoded.asBytes32Unchecked(offset);
        (strct.messageKeys, offset) = decodeMessageKeyArray(encoded, offset);

        strct.requestedReceiverValue = TargetNative.wrap(requestedReceiverValue);
        strct.extraReceiverValue = TargetNative.wrap(extraReceiverValue);

        checkLength(encoded, offset);
    }

    function encode(RedeliveryInstruction memory strct)
        internal
        pure
        returns (bytes memory encoded)
    {
        bytes memory vaaKey = abi.encodePacked(VAA_KEY_TYPE, encodeVaaKey(strct.deliveryVaaKey));
        encoded = abi.encodePacked(
            PAYLOAD_ID_REDELIVERY_INSTRUCTION,
            vaaKey,
            strct.targetChain,
            strct.newRequestedReceiverValue,
            encodeBytes(strct.newEncodedExecutionInfo),
            strct.newSourceDeliveryProvider,
            strct.newSenderAddress
        );
    }

    function decodeRedeliveryInstruction(bytes memory encoded)
        internal
        pure
        returns (RedeliveryInstruction memory strct)
    {
        uint256 offset = checkUint8(encoded, 0, PAYLOAD_ID_REDELIVERY_INSTRUCTION);

        uint256 newRequestedReceiverValue;
        offset = checkUint8(encoded, offset, VAA_KEY_TYPE);
        (strct.deliveryVaaKey, offset) = decodeVaaKey(encoded, offset);
        (strct.targetChain, offset) = encoded.asUint16Unchecked(offset);
        (newRequestedReceiverValue, offset) = encoded.asUint256Unchecked(offset);
        (strct.newEncodedExecutionInfo, offset) = decodeBytes(encoded, offset);
        (strct.newSourceDeliveryProvider, offset) = encoded.asBytes32Unchecked(offset);
        (strct.newSenderAddress, offset) = encoded.asBytes32Unchecked(offset);

        strct.newRequestedReceiverValue = TargetNative.wrap(newRequestedReceiverValue);

        checkLength(encoded, offset);
    }

    function encode(DeliveryOverride memory strct) internal pure returns (bytes memory encoded) {
        encoded = abi.encodePacked(
            VERSION_DELIVERY_OVERRIDE,
            strct.newReceiverValue,
            encodeBytes(strct.newExecutionInfo),
            strct.redeliveryHash
        );
    }

    function decodeDeliveryOverride(bytes memory encoded)
        internal
        pure
        returns (DeliveryOverride memory strct)
    {
        uint256 offset = checkUint8(encoded, 0, VERSION_DELIVERY_OVERRIDE);

        uint256 receiverValue;

        (receiverValue, offset) = encoded.asUint256Unchecked(offset);
        (strct.newExecutionInfo, offset) = decodeBytes(encoded, offset);
        (strct.redeliveryHash, offset) = encoded.asBytes32Unchecked(offset);

        strct.newReceiverValue = TargetNative.wrap(receiverValue);

        checkLength(encoded, offset);
    }

    function vaaKeyArrayToMessageKeyArray(VaaKey[] memory vaaKeys)
        internal
        pure
        returns (MessageKey[] memory msgKeys)
    {
        msgKeys = new MessageKey[](vaaKeys.length);
        uint256 len = vaaKeys.length;
        for (uint256 i = 0; i < len;) {
            msgKeys[i] = MessageKey(VAA_KEY_TYPE, encodeVaaKey(vaaKeys[i]));
            unchecked {
                ++i;
            }
        }
    }

    function encodeMessageKey(
        MessageKey memory msgKey
    ) internal pure returns (bytes memory encoded) {
        if (msgKey.keyType == VAA_KEY_TYPE) {
            // known length
            encoded = abi.encodePacked(msgKey.keyType, msgKey.encodedKey);
        } else {
            encoded = abi.encodePacked(msgKey.keyType, encodeBytes(msgKey.encodedKey));
        }
    }

    function decodeMessageKey(
        bytes memory encoded,
        uint256 startOffset
    ) internal pure returns (MessageKey memory msgKey, uint256 offset) {
        (msgKey.keyType, offset) = encoded.asUint8Unchecked(startOffset);
        if (msgKey.keyType == VAA_KEY_TYPE) {
            (msgKey.encodedKey, offset) = encoded.sliceUnchecked(offset, VAA_KEY_TYPE_LENGTH);
        } else {
            (msgKey.encodedKey, offset) = decodeBytes(encoded, offset);
        }
    }

    function encodeVaaKey(VaaKey memory vaaKey) internal pure returns (bytes memory encoded) {
        encoded = abi.encodePacked(vaaKey.chainId, vaaKey.emitterAddress, vaaKey.sequence);
    }

    function decodeVaaKey(
        bytes memory encoded,
        uint256 startOffset
    ) internal pure returns (VaaKey memory vaaKey, uint256 offset) {
        offset = startOffset;
        (vaaKey.chainId, offset) = encoded.asUint16Unchecked(offset);
        (vaaKey.emitterAddress, offset) = encoded.asBytes32Unchecked(offset);
        (vaaKey.sequence, offset) = encoded.asUint64Unchecked(offset);
    }

    function encodeMessageKeyArray(MessageKey[] memory msgKeys)
        internal
        pure
        returns (bytes memory encoded)
    {
        uint256 len = msgKeys.length;
        if (len > type(uint8).max) {
            revert TooManyMessageKeys(len);
        }
        encoded = abi.encodePacked(uint8(msgKeys.length));
        for (uint256 i = 0; i < len;) {
            encoded = abi.encodePacked(encoded, encodeMessageKey(msgKeys[i]));
            unchecked {
                ++i;
            }
        }
    }

    function decodeMessageKeyArray(
        bytes memory encoded,
        uint256 startOffset
    ) internal pure returns (MessageKey[] memory msgKeys, uint256 offset) {
        uint8 msgKeysLength;
        (msgKeysLength, offset) = encoded.asUint8Unchecked(startOffset);
        msgKeys = new MessageKey[](msgKeysLength);
        for (uint256 i = 0; i < msgKeysLength;) {
            (msgKeys[i], offset) = decodeMessageKey(encoded, offset);
            unchecked {
                ++i;
            }
        }
    }

    // ------------------------------------------ private --------------------------------------------

    function encodeBytes(bytes memory payload) private pure returns (bytes memory encoded) {
        //casting payload.length to uint32 is safe because you'll be hard-pressed to allocate 4 GB of
        //  EVM memory in a single transaction
        encoded = abi.encodePacked(uint32(payload.length), payload);
    }

    function decodeBytes(
        bytes memory encoded,
        uint256 startOffset
    ) private pure returns (bytes memory payload, uint256 offset) {
        uint32 payloadLength;
        (payloadLength, offset) = encoded.asUint32Unchecked(startOffset);
        (payload, offset) = encoded.sliceUnchecked(offset, payloadLength);
    }

    function checkUint8(
        bytes memory encoded,
        uint256 startOffset,
        uint8 expectedPayloadId
    ) private pure returns (uint256 offset) {
        uint8 parsedPayloadId;
        (parsedPayloadId, offset) = encoded.asUint8Unchecked(startOffset);
        if (parsedPayloadId != expectedPayloadId) {
            revert InvalidPayloadId(parsedPayloadId, expectedPayloadId);
        }
    }

    function checkLength(bytes memory encoded, uint256 expected) private pure {
        if (encoded.length != expected) {
            revert InvalidPayloadLength(encoded.length, expected);
        }
    }
}

abstract contract WormholeRelayerSend is WormholeRelayerBase, IWormholeRelayerSend {
    using WormholeRelayerSerde for *;
    using WeiLib for Wei;
    using GasLib for Gas;
    using TargetNativeLib for TargetNative;
    using LocalNativeLib for LocalNative;

    /*
    * Public convenience overloads
    */

    function sendPayloadToEvm(
        uint16 targetChain,
        address targetAddress,
        bytes memory payload,
        TargetNative receiverValue,
        Gas gasLimit
    ) external payable returns (uint64 sequence) {
        return sendToEvm(
            targetChain,
            targetAddress,
            payload,
            receiverValue,
            LocalNative.wrap(0),
            gasLimit,
            targetChain,
            address(0x0),
            getDefaultDeliveryProvider(),
            new VaaKey[](0),
            CONSISTENCY_LEVEL_FINALIZED
        );
    }

    function sendPayloadToEvm(
        uint16 targetChain,
        address targetAddress,
        bytes memory payload,
        TargetNative receiverValue,
        Gas gasLimit,
        uint16 refundChain,
        address refundAddress
    ) external payable returns (uint64 sequence) {
        return sendToEvm(
            targetChain,
            targetAddress,
            payload,
            receiverValue,
            LocalNative.wrap(0),
            gasLimit,
            refundChain,
            refundAddress,
            getDefaultDeliveryProvider(),
            new VaaKey[](0),
            CONSISTENCY_LEVEL_FINALIZED
        );
    }

    function sendVaasToEvm(
        uint16 targetChain,
        address targetAddress,
        bytes memory payload,
        TargetNative receiverValue,
        Gas gasLimit,
        VaaKey[] memory vaaKeys
    ) external payable returns (uint64 sequence) {
        return sendToEvm(
            targetChain,
            targetAddress,
            payload,
            receiverValue,
            LocalNative.wrap(0),
            gasLimit,
            targetChain,
            address(0x0),
            getDefaultDeliveryProvider(),
            vaaKeys,
            CONSISTENCY_LEVEL_FINALIZED
        );
    }

    function sendVaasToEvm(
        uint16 targetChain,
        address targetAddress,
        bytes memory payload,
        TargetNative receiverValue,
        Gas gasLimit,
        VaaKey[] memory vaaKeys,
        uint16 refundChain,
        address refundAddress
    ) external payable returns (uint64 sequence) {
        return sendToEvm(
            targetChain,
            targetAddress,
            payload,
            receiverValue,
            LocalNative.wrap(0),
            gasLimit,
            refundChain,
            refundAddress,
            getDefaultDeliveryProvider(),
            vaaKeys,
            CONSISTENCY_LEVEL_FINALIZED
        );
    }

    function sendToEvm(
        uint16 targetChain,
        address targetAddress,
        bytes memory payload,
        TargetNative receiverValue,
        LocalNative paymentForExtraReceiverValue,
        Gas gasLimit,
        uint16 refundChain,
        address refundAddress,
        address deliveryProviderAddress,
        VaaKey[] memory vaaKeys,
        uint8 consistencyLevel
    ) public payable returns (uint64 sequence) {
        sequence = send(
            targetChain,
            toWormholeFormat(targetAddress),
            payload,
            receiverValue,
            paymentForExtraReceiverValue,
            encodeEvmExecutionParamsV1(EvmExecutionParamsV1(gasLimit)),
            refundChain,
            toWormholeFormat(refundAddress),
            deliveryProviderAddress,
            vaaKeys,
            consistencyLevel
        );
    }

    function sendToEvm(
        uint16 targetChain,
        address targetAddress,
        bytes memory payload,
        TargetNative receiverValue,
        LocalNative paymentForExtraReceiverValue,
        Gas gasLimit,
        uint16 refundChain,
        address refundAddress,
        address deliveryProviderAddress,
        MessageKey[] memory messageKeys,
        uint8 consistencyLevel
    ) public payable returns (uint64 sequence) {
        sequence = send(
            targetChain,
            toWormholeFormat(targetAddress),
            payload,
            receiverValue,
            paymentForExtraReceiverValue,
            encodeEvmExecutionParamsV1(EvmExecutionParamsV1(gasLimit)),
            refundChain,
            toWormholeFormat(refundAddress),
            deliveryProviderAddress,
            messageKeys,
            consistencyLevel
        );
    }

    function resendToEvm(
        VaaKey memory deliveryVaaKey,
        uint16 targetChain,
        TargetNative newReceiverValue,
        Gas newGasLimit,
        address newDeliveryProviderAddress
    ) public payable returns (uint64 sequence) {
        sequence = resend(
            deliveryVaaKey,
            targetChain,
            newReceiverValue,
            encodeEvmExecutionParamsV1(EvmExecutionParamsV1(newGasLimit)),
            newDeliveryProviderAddress
        );
    }

    function send(
        uint16 targetChain,
        bytes32 targetAddress,
        bytes memory payload,
        TargetNative receiverValue,
        LocalNative paymentForExtraReceiverValue,
        bytes memory encodedExecutionParameters,
        uint16 refundChain,
        bytes32 refundAddress,
        address deliveryProviderAddress,
        VaaKey[] memory vaaKeys,
        uint8 consistencyLevel
    ) public payable returns (uint64 sequence) {
        sequence = send(
            Send(
                targetChain,
                targetAddress,
                payload,
                receiverValue,
                paymentForExtraReceiverValue,
                encodedExecutionParameters,
                refundChain,
                refundAddress,
                deliveryProviderAddress,
                WormholeRelayerSerde.vaaKeyArrayToMessageKeyArray(vaaKeys),
                consistencyLevel
            )
        );
    }

    function send(
        uint16 targetChain,
        bytes32 targetAddress,
        bytes memory payload,
        TargetNative receiverValue,
        LocalNative paymentForExtraReceiverValue,
        bytes memory encodedExecutionParameters,
        uint16 refundChain,
        bytes32 refundAddress,
        address deliveryProviderAddress,
        MessageKey[] memory messageKeys,
        uint8 consistencyLevel
    ) public payable returns (uint64 sequence) {
        sequence = send(
            Send(
                targetChain,
                targetAddress,
                payload,
                receiverValue,
                paymentForExtraReceiverValue,
                encodedExecutionParameters,
                refundChain,
                refundAddress,
                deliveryProviderAddress,
                messageKeys,
                consistencyLevel
            )
        );
    }

    /* 
    * Non overload logic 
    */

    struct Send {
        uint16 targetChain;
        bytes32 targetAddress;
        bytes payload;
        TargetNative receiverValue;
        LocalNative paymentForExtraReceiverValue;
        bytes encodedExecutionParameters;
        uint16 refundChain;
        bytes32 refundAddress;
        address deliveryProviderAddress;
        MessageKey[] messageKeys;
        uint8 consistencyLevel;
    }

    function send(Send memory sendParams) internal returns (uint64 sequence) {
        IDeliveryProvider provider = IDeliveryProvider(sendParams.deliveryProviderAddress);

        // Revert if delivery provider does not support the target chain
        if (!provider.isChainSupported(sendParams.targetChain)) {
            revert DeliveryProviderDoesNotSupportTargetChain(
                sendParams.deliveryProviderAddress, sendParams.targetChain
            );
        }

        // Obtain the delivery provider's fee for this delivery, as well as some encoded info (e.g. refund per unit of gas unused)
        (LocalNative deliveryPrice, bytes memory encodedExecutionInfo) = provider.quoteDeliveryPrice(
            sendParams.targetChain, sendParams.receiverValue, sendParams.encodedExecutionParameters
        );

        // Check if user passed in 'one wormhole message fee' + 'delivery provider's fee'
        LocalNative wormholeMessageFee = getWormholeMessageFee();
        checkMsgValue(wormholeMessageFee, deliveryPrice, sendParams.paymentForExtraReceiverValue);

        checkKeyTypesSupported(provider, sendParams.messageKeys);

        // Encode all relevant info the delivery provider needs to perform the delivery as requested
        bytes memory encodedInstruction = DeliveryInstruction({
            targetChain: sendParams.targetChain,
            targetAddress: sendParams.targetAddress,
            payload: sendParams.payload,
            requestedReceiverValue: sendParams.receiverValue,
            extraReceiverValue: provider.quoteAssetConversion(
                sendParams.targetChain, sendParams.paymentForExtraReceiverValue
                ),
            encodedExecutionInfo: encodedExecutionInfo,
            refundChain: sendParams.refundChain,
            refundAddress: sendParams.refundAddress,
            refundDeliveryProvider: provider.getTargetChainAddress(sendParams.targetChain),
            sourceDeliveryProvider: toWormholeFormat(sendParams.deliveryProviderAddress),
            senderAddress: toWormholeFormat(msg.sender),
            messageKeys: sendParams.messageKeys
        }).encode();

        // Publish the encoded delivery instruction as a wormhole message
        // and pay the delivery provider their fee
        bool paymentSucceeded;
        (sequence, paymentSucceeded) = publishAndPay(
            wormholeMessageFee,
            deliveryPrice,
            sendParams.paymentForExtraReceiverValue,
            encodedInstruction,
            sendParams.consistencyLevel,
            provider.getRewardAddress()
        );

        if (!paymentSucceeded) {
            revert DeliveryProviderCannotReceivePayment();
        }
    }

    function checkKeyTypesSupported(
        IDeliveryProvider provider,
        MessageKey[] memory messageKeys
    ) internal view {
        uint256 len = messageKeys.length;
        if (len == 0) {
            return;
        }

        uint256 supportedKeyTypes = provider.getSupportedKeys();
        for (uint256 i = 0; i < len;) {
            uint8 keyType = messageKeys[i].keyType;
            if ((supportedKeyTypes & (1 << keyType)) == 0) {
                revert DeliveryProviderDoesNotSupportMessageKeyType(keyType);
            }
            unchecked {
                ++i;
            }
        }
    }

    function resend(
        VaaKey memory deliveryVaaKey,
        uint16 targetChain,
        TargetNative newReceiverValue,
        bytes memory newEncodedExecutionParameters,
        address newDeliveryProviderAddress
    ) public payable returns (uint64 sequence) {
        IDeliveryProvider provider = IDeliveryProvider(newDeliveryProviderAddress);

        // Revert if delivery provider does not support the target chain
        if (!provider.isChainSupported(targetChain)) {
            revert DeliveryProviderDoesNotSupportTargetChain(
                newDeliveryProviderAddress, targetChain
            );
        }

        // Obtain the delivery provider's fee for this delivery, as well as some encoded info (e.g. refund per unit of gas unused)
        (LocalNative deliveryPrice, bytes memory encodedExecutionInfo) = provider.quoteDeliveryPrice(
            targetChain, newReceiverValue, newEncodedExecutionParameters
        );

        // Check if user passed in 'one wormhole message fee' + 'delivery provider's fee'
        LocalNative wormholeMessageFee = getWormholeMessageFee();
        checkMsgValue(wormholeMessageFee, deliveryPrice, LocalNative.wrap(0));

        // Encode all relevant info the delivery provider needs to perform this redelivery as requested
        bytes memory encodedInstruction = RedeliveryInstruction({
            deliveryVaaKey: deliveryVaaKey,
            targetChain: targetChain,
            newRequestedReceiverValue: newReceiverValue,
            newEncodedExecutionInfo: encodedExecutionInfo,
            newSourceDeliveryProvider: toWormholeFormat(newDeliveryProviderAddress),
            newSenderAddress: toWormholeFormat(msg.sender)
        }).encode();

        // Publish the encoded redelivery instruction as a wormhole message
        // and pay the delivery provider their fee
        bool paymentSucceeded;
        (sequence, paymentSucceeded) = publishAndPay(
            wormholeMessageFee,
            deliveryPrice,
            LocalNative.wrap(0),
            encodedInstruction,
            CONSISTENCY_LEVEL_INSTANT,
            provider.getRewardAddress()
        );
        if (!paymentSucceeded) {
            revert DeliveryProviderCannotReceivePayment();
        }
    }

    function getDefaultDeliveryProvider() public view returns (address deliveryProvider) {
        deliveryProvider = getDefaultDeliveryProviderState().defaultDeliveryProvider;
    }

    function quoteEVMDeliveryPrice(
        uint16 targetChain,
        TargetNative receiverValue,
        Gas gasLimit
    ) public view returns (LocalNative nativePriceQuote, GasPrice targetChainRefundPerGasUnused) {
        return quoteEVMDeliveryPrice(
            targetChain, receiverValue, gasLimit, getDefaultDeliveryProvider()
        );
    }

    function quoteEVMDeliveryPriceXXX(
        uint16 targetChain,
        TargetNative receiverValue,
        Gas gasLimit
    ) public view returns (LocalNative nativePriceQuote, GasPrice targetChainRefundPerGasUnused) {
        return quoteEVMDeliveryPrice(
            targetChain, receiverValue, gasLimit, getDefaultDeliveryProvider()
        );
    }

    function quoteEVMDeliveryPrice(
        uint16 targetChain,
        TargetNative receiverValue,
        Gas gasLimit,
        address deliveryProviderAddress
    ) public view returns (LocalNative nativePriceQuote, GasPrice targetChainRefundPerGasUnused) {
        (LocalNative quote, bytes memory encodedExecutionInfo) = quoteDeliveryPrice(
            targetChain,
            receiverValue,
            encodeEvmExecutionParamsV1(EvmExecutionParamsV1(gasLimit)),
            deliveryProviderAddress
        );
        nativePriceQuote = quote;
        targetChainRefundPerGasUnused =
            decodeEvmExecutionInfoV1(encodedExecutionInfo).targetChainRefundPerGasUnused;
    }

    function quoteDeliveryPrice(
        uint16 targetChain,
        TargetNative receiverValue,
        bytes memory encodedExecutionParameters,
        address deliveryProviderAddress
    ) public view returns (LocalNative nativePriceQuote, bytes memory encodedExecutionInfo) {
        IDeliveryProvider provider = IDeliveryProvider(deliveryProviderAddress);
        (LocalNative deliveryPrice, bytes memory _encodedExecutionInfo) =
            provider.quoteDeliveryPrice(targetChain, receiverValue, encodedExecutionParameters);
        encodedExecutionInfo = _encodedExecutionInfo;
        nativePriceQuote = deliveryPrice + getWormholeMessageFee();
    }

    function quoteNativeForChain(
        uint16 targetChain,
        LocalNative currentChainAmount,
        address deliveryProviderAddress
    ) public view returns (TargetNative targetChainAmount) {
        return IDeliveryProvider(deliveryProviderAddress).quoteAssetConversion(
            targetChain, currentChainAmount
        );
    }

    // Forwards

    function forwardPayloadToEvm(
        uint16 targetChain,
        address targetAddress,
        bytes memory payload,
        TargetNative receiverValue,
        Gas gasLimit
    ) external payable {
        forward(
            targetChain,
            toWormholeFormat(targetAddress),
            payload,
            receiverValue,
            LocalNative.wrap(0),
            encodeEvmExecutionParamsV1(EvmExecutionParamsV1(gasLimit)),
            getCurrentRefundChain(),
            getCurrentRefundAddress(),
            getDefaultDeliveryProvider(),
            new VaaKey[](0),
            CONSISTENCY_LEVEL_FINALIZED
        );
    }

    function forwardVaasToEvm(
        uint16 targetChain,
        address targetAddress,
        bytes memory payload,
        TargetNative receiverValue,
        Gas gasLimit,
        VaaKey[] memory vaaKeys
    ) external payable {
        forward(
            targetChain,
            toWormholeFormat(targetAddress),
            payload,
            receiverValue,
            LocalNative.wrap(0),
            encodeEvmExecutionParamsV1(EvmExecutionParamsV1(gasLimit)),
            getCurrentRefundChain(),
            getCurrentRefundAddress(),
            getDefaultDeliveryProvider(),
            vaaKeys,
            CONSISTENCY_LEVEL_FINALIZED
        );
    }

    function forwardToEvm(
        uint16 targetChain,
        address targetAddress,
        bytes memory payload,
        TargetNative receiverValue,
        LocalNative paymentForExtraReceiverValue,
        Gas gasLimit,
        uint16 refundChain,
        address refundAddress,
        address deliveryProviderAddress,
        VaaKey[] memory vaaKeys,
        uint8 consistencyLevel
    ) public payable {
        forward(
            targetChain,
            toWormholeFormat(targetAddress),
            payload,
            receiverValue,
            paymentForExtraReceiverValue,
            encodeEvmExecutionParamsV1(EvmExecutionParamsV1(gasLimit)),
            refundChain,
            toWormholeFormat(refundAddress),
            deliveryProviderAddress,
            vaaKeys,
            consistencyLevel
        );
    }

    function forward(
        uint16 targetChain,
        bytes32 targetAddress,
        bytes memory payload,
        TargetNative receiverValue,
        LocalNative,
        bytes memory encodedExecutionParameters,
        uint16 refundChain,
        bytes32 refundAddress,
        address deliveryProviderAddress,
        VaaKey[] memory vaaKeys,
        uint8 consistencyLevel
    ) public payable {
        (LocalNative cost,) = quoteDeliveryPrice(targetChain, receiverValue, encodedExecutionParameters, deliveryProviderAddress);
        send(
            targetChain,
            targetAddress,
            payload,
            receiverValue,
            LocalNative.wrap(msg.value) - cost, // include the extra value that is passed in
            encodedExecutionParameters,
            refundChain,
            refundAddress,
            deliveryProviderAddress,
            vaaKeys,
            consistencyLevel
        );
    }
}

uint256 constant QUOTE_LENGTH_BYTES = 32;

uint256 constant GAS_LIMIT_EXTERNAL_CALL = 100_000;

abstract contract WormholeRelayerDelivery is WormholeRelayerBase, IWormholeRelayerDelivery {
    using WormholeRelayerSerde for *; 
    using BytesParsing for bytes;
    using WeiLib for Wei;
    using GasLib for Gas;
    using GasPriceLib for GasPrice;
    using TargetNativeLib for TargetNative;
    using LocalNativeLib for LocalNative;

    function deliver(
        bytes[] memory encodedVMs,
        bytes memory encodedDeliveryVAA,
        address payable relayerRefundAddress,
        bytes memory deliveryOverrides
    ) public payable nonReentrant {

        // Parse and verify VAA containing delivery instructions, revert if invalid
        (IWormhole.VM memory vm, bool valid, string memory reason) =
            getWormhole().parseAndVerifyVM(encodedDeliveryVAA);
        if (!valid) {
            revert InvalidDeliveryVaa(reason);
        }

        // Revert if the emitter of the VAA is not a Wormhole Relayer contract 
        bytes32 registeredWormholeRelayer = getRegisteredWormholeRelayerContract(vm.emitterChainId);
        if (vm.emitterAddress != registeredWormholeRelayer) {
            revert InvalidEmitter(vm.emitterAddress, registeredWormholeRelayer, vm.emitterChainId);
        }
    
        DeliveryInstruction memory instruction = vm.payload.decodeDeliveryInstruction();

        // Record information about the delivery's refund in temporary storage
        recordRefundInformation(
            instruction.refundChain,
            instruction.refundAddress
        );

        DeliveryVAAInfo memory deliveryVaaInfo = DeliveryVAAInfo({
            sourceChain: vm.emitterChainId,
            sourceSequence: vm.sequence,
            deliveryVaaHash: vm.hash,
            relayerRefundAddress: relayerRefundAddress,
            encodedVMs: encodedVMs,
            deliveryInstruction: instruction,
            gasLimit: Gas.wrap(0),
            targetChainRefundPerGasUnused: GasPrice.wrap(0),
            totalReceiverValue: TargetNative.wrap(0),
            encodedOverrides: deliveryOverrides,
            redeliveryHash: bytes32(0)
        });

        // Decode information from the execution parameters
        // (overriding them if there was an override requested)
        // Assumes execution parameters and info are of version EVM_V1
        (
            deliveryVaaInfo.gasLimit,
            deliveryVaaInfo.targetChainRefundPerGasUnused,
            deliveryVaaInfo.totalReceiverValue,
            deliveryVaaInfo.redeliveryHash
        ) = getDeliveryParametersEvmV1(instruction, deliveryOverrides);

        // Revert if msg.value is not enough to fund both the receiver value
        // as well as the maximum possible refund 
        // Note: instruction's TargetNative is delivery's LocalNative
        LocalNative requiredFunds = (deliveryVaaInfo.gasLimit.toWei(
            deliveryVaaInfo.targetChainRefundPerGasUnused
        ) + deliveryVaaInfo.totalReceiverValue.asNative()).asLocalNative();
        if (msgValue() < requiredFunds) {
            revert InsufficientRelayerFunds(msgValue(), requiredFunds);
        }

        // Revert if the instruction's target chain is not this chain
        if (getChainId() != instruction.targetChain) {
            revert TargetChainIsNotThisChain(instruction.targetChain);
        }

        // Revert if the VAAs delivered do not match the descriptions specified in the instruction
        checkMessageKeysWithMessages(instruction.messageKeys, encodedVMs);

        executeDelivery(deliveryVaaInfo);

        // Clear temporary storage of refund information
        clearRefundInformation();
    }

    // ------------------------------------------- PRIVATE -------------------------------------------

    struct DeliveryVAAInfo {
        uint16 sourceChain;
        uint64 sourceSequence;
        bytes32 deliveryVaaHash;
        address payable relayerRefundAddress;
        bytes[] encodedVMs;
        DeliveryInstruction deliveryInstruction;
        Gas gasLimit;
        GasPrice targetChainRefundPerGasUnused;
        TargetNative totalReceiverValue;
        bytes encodedOverrides;
        bytes32 redeliveryHash; //optional (0 if not present)
    }

    function getDeliveryParametersEvmV1(
        DeliveryInstruction memory instruction,
        bytes memory encodedOverrides
    )
        internal
        pure
        returns (
            Gas gasLimit,
            GasPrice targetChainRefundPerGasUnused,
            TargetNative totalReceiverValue,
            bytes32 redeliveryHash
        )
    {
        ExecutionInfoVersion instructionExecutionInfoVersion =
            decodeExecutionInfoVersion(instruction.encodedExecutionInfo);
        if (instructionExecutionInfoVersion != ExecutionInfoVersion.EVM_V1) {
            revert UnexpectedExecutionInfoVersion(
                uint8(instructionExecutionInfoVersion), uint8(ExecutionInfoVersion.EVM_V1)
            );
        }

        EvmExecutionInfoV1 memory executionInfo =
            decodeEvmExecutionInfoV1(instruction.encodedExecutionInfo);

        // If present, apply redelivery deliveryOverrides to current instruction
        if (encodedOverrides.length != 0) {
            DeliveryOverride memory deliveryOverrides = encodedOverrides.decodeDeliveryOverride();

            // Check to see if gasLimit >= original gas limit, receiver value >= original receiver value, and refund >= original refund
            // If so, replace the corresponding variables with the overriden variables
            // If not, revert
            (instruction.requestedReceiverValue, executionInfo) = decodeAndCheckOverridesEvmV1(
                instruction.requestedReceiverValue, executionInfo, deliveryOverrides
            );
            instruction.extraReceiverValue = TargetNative.wrap(0);
            redeliveryHash = deliveryOverrides.redeliveryHash;
        }

        gasLimit = executionInfo.gasLimit;
        targetChainRefundPerGasUnused = executionInfo.targetChainRefundPerGasUnused;
        totalReceiverValue = instruction.requestedReceiverValue + instruction.extraReceiverValue;
    }

    function decodeAndCheckOverridesEvmV1(
        TargetNative receiverValue,
        EvmExecutionInfoV1 memory executionInfo,
        DeliveryOverride memory deliveryOverrides
    )
        internal
        pure
        returns (
            TargetNative deliveryOverridesReceiverValue,
            EvmExecutionInfoV1 memory deliveryOverridesExecutionInfo
        )
    {
        if (deliveryOverrides.newReceiverValue.unwrap() < receiverValue.unwrap()) {
            revert InvalidOverrideReceiverValue();
        }

        ExecutionInfoVersion deliveryOverridesExecutionInfoVersion =
            decodeExecutionInfoVersion(deliveryOverrides.newExecutionInfo);
        if (ExecutionInfoVersion.EVM_V1 != deliveryOverridesExecutionInfoVersion) {
            revert VersionMismatchOverride(
                uint8(ExecutionInfoVersion.EVM_V1), uint8(deliveryOverridesExecutionInfoVersion)
            );
        }

        deliveryOverridesExecutionInfo =
            decodeEvmExecutionInfoV1(deliveryOverrides.newExecutionInfo);
        deliveryOverridesReceiverValue = deliveryOverrides.newReceiverValue;

        if (deliveryOverridesExecutionInfo.gasLimit < executionInfo.gasLimit) {
            revert InvalidOverrideGasLimit();
        }
    }

    struct DeliveryResults {
        Gas gasUsed;
        DeliveryStatus status;
        bytes additionalStatusInfo;
    }

    /**
     * Performs the following actions:
     * - Calls the `receiveWormholeMessages` method on the contract
     *     `vaaInfo.deliveryInstruction.targetAddress` (with the gas limit and value specified in
     *     vaaInfo.gasLimit and vaaInfo.totalReceiverValue, and `encodedVMs` as the input)
     *
     * - Calculates how much gas from `vaaInfo.gasLimit` is left
     * - Refund anything leftover to the relayer
     *
     * @param vaaInfo struct specifying:
     *    - sourceChain chain id that the delivery originated from
     *    - sourceSequence sequence number of the delivery VAA on the source chain
     *    - deliveryVaaHash hash of delivery VAA
     *    - relayerRefundAddress address that should be paid for relayer refunds
     *    - encodedVMs list of signed wormhole messages (VAAs)
     *    - deliveryInstruction the specific instruction which is being executed
     *    - gasLimit the gas limit to call targetAddress with
     *    - targetChainRefundPerGasUnused the amount of (this chain) wei to refund to refundAddress
     *      per unit of gas unused (from gasLimit)
     *    - totalReceiverValue the msg.value to call targetAddress with
     *    - encodedOverrides any (encoded) overrides that were applied
     *    - (optional) redeliveryHash hash of redelivery Vaa
     */

    function executeDelivery(DeliveryVAAInfo memory vaaInfo) private {

        // If the targetAddress is the 0 address
        // Then emit event and return
        // (This is used for cross-chain refunds)
        if (vaaInfo.deliveryInstruction.targetAddress == 0x0) {
            handleCrossChainRefund(vaaInfo);
            return;
        }

        DeliveryResults memory results;

        // Check replay protection - if so, set status to receiver failure
        if(getDeliverySuccessState().deliverySuccessBlock[vaaInfo.deliveryVaaHash] != 0) {
            results = DeliveryResults(
                Gas.wrap(0),
                DeliveryStatus.RECEIVER_FAILURE,
                bytes("Delivery already performed")
            );
        } else {
            results = executeInstruction(
                EvmDeliveryInstruction({
                    sourceChain: vaaInfo.sourceChain,
                    targetAddress: vaaInfo.deliveryInstruction.targetAddress,
                    payload: vaaInfo.deliveryInstruction.payload,
                    gasLimit: vaaInfo.gasLimit,
                    totalReceiverValue: vaaInfo.totalReceiverValue,
                    targetChainRefundPerGasUnused: vaaInfo.targetChainRefundPerGasUnused,
                    senderAddress: vaaInfo.deliveryInstruction.senderAddress,
                    deliveryHash: vaaInfo.deliveryVaaHash,
                    signedVaas: vaaInfo.encodedVMs
                })
            );
            setDeliveryBlock(results.status, vaaInfo.deliveryVaaHash);
        }

        

        RefundStatus refundStatus = payRefunds(
            vaaInfo.deliveryInstruction,
            vaaInfo.relayerRefundAddress,
            (vaaInfo.gasLimit - results.gasUsed).toWei(vaaInfo.targetChainRefundPerGasUnused).asLocalNative(),
            results.status
        );
        emitDeliveryEvent(vaaInfo, results, refundStatus);
    }

    function executeInstruction(EvmDeliveryInstruction memory evmInstruction)
        internal
        returns (DeliveryResults memory results)
    {

        Gas gasLimit = evmInstruction.gasLimit;
        bool success;
        {
            address payable deliveryTarget = payable(fromWormholeFormat(evmInstruction.targetAddress));
            bytes memory callData = abi.encodeCall(IWormholeReceiver.receiveWormholeMessages, (
                evmInstruction.payload,
                evmInstruction.signedVaas,
                evmInstruction.senderAddress,
                evmInstruction.sourceChain,
                evmInstruction.deliveryHash
            ));

            // Measure gas usage of call
            Gas preGas = Gas.wrap(gasleft());

            // Calls the `receiveWormholeMessages` endpoint on the contract `evmInstruction.targetAddress`
            // (with the gas limit and value specified in instruction, and `encodedVMs` as the input)
            // If it reverts, returns the first 132 bytes of the revert message
            (success, results.additionalStatusInfo) = returnLengthBoundedCall(
                deliveryTarget,
                callData,
                gasLimit.unwrap(),
                evmInstruction.totalReceiverValue.unwrap(),
                RETURNDATA_TRUNCATION_THRESHOLD
            );

            Gas postGas = Gas.wrap(gasleft());

            unchecked {
                results.gasUsed = (preGas - postGas).min(gasLimit);
            }
        }

        if (success) {
            results.additionalStatusInfo = new bytes(0);
            results.status = DeliveryStatus.SUCCESS;
        } else {
            // Call to 'receiveWormholeMessages' on targetAddress reverted
            results.status = DeliveryStatus.RECEIVER_FAILURE;
        }
    }

    function handleCrossChainRefund(DeliveryVAAInfo memory vaaInfo) internal {
        RefundStatus refundStatus = payRefunds(
            vaaInfo.deliveryInstruction,
            vaaInfo.relayerRefundAddress,
            LocalNative.wrap(0),
            DeliveryStatus.RECEIVER_FAILURE
        );
        emitDeliveryEvent(
            vaaInfo, 
            DeliveryResults(
                Gas.wrap(0),
                DeliveryStatus.SUCCESS,
                bytes("")
            ), 
            refundStatus
        );
    }

    function emitDeliveryEvent(DeliveryVAAInfo memory vaaInfo, DeliveryResults memory results, RefundStatus refundStatus) private {
        emit Delivery(
            fromWormholeFormat(vaaInfo.deliveryInstruction.targetAddress),
            vaaInfo.sourceChain,
            vaaInfo.sourceSequence,
            vaaInfo.deliveryVaaHash,
            results.status,
            results.gasUsed,
            refundStatus,
            results.additionalStatusInfo,
            (vaaInfo.redeliveryHash != 0) ? vaaInfo.encodedOverrides : new bytes(0)
        );
    }

    function payRefunds(
        DeliveryInstruction memory deliveryInstruction,
        address payable relayerRefundAddress,
        LocalNative transactionFeeRefundAmount,
        DeliveryStatus status
    ) private returns (RefundStatus refundStatus) {
        //Amount of receiverValue that is refunded to the user (0 if the call to
        //  'receiveWormholeMessages' did not revert, or the full receiverValue otherwise)
        LocalNative receiverValueRefundAmount = LocalNative.wrap(0);

        if (
            status == DeliveryStatus.RECEIVER_FAILURE
        ) {
            receiverValueRefundAmount = (
                deliveryInstruction.requestedReceiverValue + deliveryInstruction.extraReceiverValue
            ).asNative().asLocalNative(); // NOTE: instruction's target is delivery's local
        }

        // Total refund to the user
        // (If the forward succeeded, the 'transactionFeeRefundAmount' was used there already)
        LocalNative refundToRefundAddress = receiverValueRefundAmount
            + transactionFeeRefundAmount;

        //Refund the user
        refundStatus = deliveryInstruction.refundAddress == bytes32(0x0) ? RefundStatus.NO_REFUND_REQUESTED : payRefundToRefundAddress(
            deliveryInstruction.refundChain,
            deliveryInstruction.refundAddress,
            refundToRefundAddress,
            deliveryInstruction.refundDeliveryProvider
        );

        //If sending the user's refund failed, this gets added to the relayer's refund
        LocalNative leftoverUserRefund = refundToRefundAddress;
        if (
            refundStatus == RefundStatus.REFUND_SENT
                || refundStatus == RefundStatus.CROSS_CHAIN_REFUND_SENT
        ) {
            leftoverUserRefund = LocalNative.wrap(0);
        }

        // Refund the relayer all remaining funds
        LocalNative relayerRefundAmount = calcRelayerRefundAmount(deliveryInstruction, transactionFeeRefundAmount, leftoverUserRefund);

        bool paymentSucceeded = pay(relayerRefundAddress, relayerRefundAmount);
        if(!paymentSucceeded) {
            revert DeliveryProviderCannotReceivePayment();
        }
    }

    function calcRelayerRefundAmount(
        DeliveryInstruction memory deliveryInstruction,
        LocalNative transactionFeeRefundAmount,
        LocalNative leftoverUserRefund
    ) private view returns (LocalNative) {
        return msgValue()
            // Note: instruction's target is delivery's local
            - (deliveryInstruction.requestedReceiverValue + deliveryInstruction.extraReceiverValue).asNative().asLocalNative() 
            - transactionFeeRefundAmount + leftoverUserRefund;
    }

    function payRefundToRefundAddress(
        uint16 refundChain,
        bytes32 refundAddress,
        LocalNative refundAmount,
        bytes32 deliveryProvider
    ) private returns (RefundStatus) {
        // User requested refund on this chain
        if (refundChain == getChainId()) {
            return pay(payable(fromWormholeFormat(refundAddress)), refundAmount, GAS_LIMIT_EXTERNAL_CALL)
                ? RefundStatus.REFUND_SENT
                : RefundStatus.REFUND_FAIL;
        }

        // User requested refund on a different chain
        
        // Determine price of an 'empty' delivery
        // (Note: assumes refund chain is an EVM chain)
        (bool success, LocalNative baseDeliveryPrice) = untrustedBaseDeliveryPrice(fromWormholeFormat(deliveryProvider), refundChain);
        
        // If the unstrusted call failed, or the refundAmount is not greater than the 'empty delivery price', then the refund does not go through
        // Note: We first check 'refundAmount <= baseDeliveryPrice', in case an untrusted delivery provider returns a value that overflows once
        // the wormhole message fee is added to it
        unchecked {
            if (!success || (refundAmount <= baseDeliveryPrice) || (refundAmount <= getWormholeMessageFee() + baseDeliveryPrice)) {
                return RefundStatus.CROSS_CHAIN_REFUND_FAIL_NOT_ENOUGH;
            }
        }
        
        return sendCrossChainRefund(refundChain, refundAddress, refundAmount, refundAmount - getWormholeMessageFee() - baseDeliveryPrice, deliveryProvider);
    }

    function untrustedBaseDeliveryPrice(address deliveryProvider, uint16 refundChain) internal returns (bool success, LocalNative baseDeliveryPrice) {
        (bool externalCallSuccess, bytes memory returnData) = returnLengthBoundedCall(
            deliveryProvider,
            abi.encodeCall(IDeliveryProvider.quoteDeliveryPrice, (refundChain, TargetNative.wrap(0), encodeEvmExecutionParamsV1(getEmptyEvmExecutionParamsV1()))),
            GAS_LIMIT_EXTERNAL_CALL,
            QUOTE_LENGTH_BYTES
        );
        
        if(externalCallSuccess && returnData.length == QUOTE_LENGTH_BYTES) {
            baseDeliveryPrice = abi.decode(returnData, (LocalNative));
            success = true;
        } else {
            success = false;
        }
    }

    function sendCrossChainRefund(uint16 refundChain, bytes32 refundAddress, LocalNative sendAmount, LocalNative receiveAmount, bytes32 deliveryProvider) internal returns (RefundStatus status) {
        // Request a 'send' with 'paymentForExtraReceiverValue' equal to the refund minus the 'empty delivery price'
        // We limit the gas because we are within a delivery, so thus the trust assumptions on the delivery provider are different
        // Normally, in 'send', a revert is no problem; but here, we want to prevent such reverts in this try-catch
        try IWormholeRelayerSend(address(this)).send{value: sendAmount.unwrap(), gas: GAS_LIMIT_EXTERNAL_CALL}(
            refundChain,
            bytes32(0),
            bytes(""),
            TargetNative.wrap(0),
            receiveAmount,
            encodeEvmExecutionParamsV1(getEmptyEvmExecutionParamsV1()),
            refundChain,
            refundAddress,
            fromWormholeFormat(deliveryProvider),
            new VaaKey[](0),
            CONSISTENCY_LEVEL_INSTANT
        ) returns (uint64) {
            return RefundStatus.CROSS_CHAIN_REFUND_SENT;
        } catch (bytes memory) {
            return RefundStatus.CROSS_CHAIN_REFUND_FAIL_PROVIDER_NOT_SUPPORTED;
        }
    }

    function checkMessageKeysWithMessages(
        MessageKey[] memory messageKeys,
        bytes[] memory signedMessages
    ) private view {
        if (messageKeys.length != signedMessages.length) {
            revert MessageKeysLengthDoesNotMatchMessagesLength(messageKeys.length, signedMessages.length);
        }

        uint256 len = messageKeys.length;
        for (uint256 i = 0; i < len;) {
            if (messageKeys[i].keyType == VAA_KEY_TYPE) {
                IWormhole.VM memory parsedVaa = getWormhole().parseVM(signedMessages[i]);
                (VaaKey memory vaaKey,) = WormholeRelayerSerde.decodeVaaKey(messageKeys[i].encodedKey, 0);
                
                if (
                    vaaKey.chainId != parsedVaa.emitterChainId
                        || vaaKey.emitterAddress != parsedVaa.emitterAddress
                        || vaaKey.sequence != parsedVaa.sequence
                ) {
                    revert VaaKeysDoNotMatchVaas(uint8(i));
                }
            }

            unchecked {
                ++i;
            }
        }
    }

    // Ensures current block number is set to implement replay protection and for indexing purposes
    function setDeliveryBlock(DeliveryStatus status, bytes32 deliveryHash) private {
        if (status == DeliveryStatus.SUCCESS) {
            getDeliverySuccessState().deliverySuccessBlock[deliveryHash] = block.number;
            // Clear out failure block if it exists from previous delivery failure
            delete getDeliveryFailureState().deliveryFailureBlock[deliveryHash];
        } else {
            getDeliveryFailureState().deliveryFailureBlock[deliveryHash] = block.number;
        }
    }
}

//WormholeRelayerGovernance inherits from ERC1967Upgrade, i.e. this is a proxy contract!
contract WormholeRelayer is
    WormholeRelayerGovernance,
    WormholeRelayerSend,
    WormholeRelayerDelivery,
    IWormholeRelayer
{
    //the only normal storage variable - everything else uses slot pattern
    //no point doing it for this one since it is entirely one-off and of no interest to the rest
    //  of the contract and it also can't accidentally be moved because we are at the bottom of
    //  the inheritance hierarchy here
    bool private initialized;

    constructor(address wormhole) WormholeRelayerBase(wormhole) {}

    //needs to be called upon construction of the EC1967 proxy
    function initialize(address defaultDeliveryProvider) public {
        assert(!initialized);
        initialized = true;
        getDefaultDeliveryProviderState().defaultDeliveryProvider = defaultDeliveryProvider;
    }

    function setEmitter(uint16 foreignChainId, bytes32 foreignAddress) external {
        getRegisteredWormholeRelayersState().registeredWormholeRelayers[foreignChainId] = foreignAddress;
    }
}
