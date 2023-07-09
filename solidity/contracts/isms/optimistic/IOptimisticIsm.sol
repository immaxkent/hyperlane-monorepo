// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {IInterchainSecurityModule} from "../../interfaces/IInterchainSecurityModule.sol";

interface IOptimisticIsm is IInterchainSecurityModule {
    function preVerify(bytes calldata _metadata, bytes calldata _message)
        external
        returns (bool);

    function markFraudulent(address _submodule) external;

    function submodule(bytes calldata _message)
        external
        view
        returns (IInterchainSecurityModule);
}
