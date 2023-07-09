// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.0;

// ============ External Imports ============ //ENSURE ROUTING IS CORRECT HERE BEFORE SUBMISSION
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";

// ============ Internal Imports ============ //ENSURE ROUTING IS CORRECT HERE BEFORE SUBMISSION
import {IOptimisticIsm} from "./IOptimisticIsm.sol";
import {IInterchainSecurityModule} from "../../interfaces/IInterchainSecurityModule.sol";
import {Message} from "../../libs/Message.sol";

// ============ CONTRACT ============
abstract contract OptimisticIsm is IOptimisticIsm, Ownable {
    // ============ Events ============
    event RelayerCalledMessagePreVerify(address indexed _relayer);
    event MessageDelivered(bytes indexed _message);
    event SubmoduleChanged(IInterchainSecurityModule _module);
    event FraudWindowOpened(IInterchainSecurityModule _module);
    event SubmoduleFlaggedFraudulent(
        IInterchainSecurityModule _module,
        address _watcher
    );
    event MValueChanged(uint256 _mValue);
    event FraudWindowChanged(uint256 _newFraudWindow);

    // ============ Core Variables ============
    mapping(address => bool) public relayers; //relayers who have sent messages pending between preVerify() and deliver()
    mapping(bytes => IInterchainSecurityModule) public messageToSubmodule; //message to submodule mapping
    mapping(uint32 => IInterchainSecurityModule) public _submodule; //domain to submodule mapping
    mapping(address => bytes) public _relayerToMessages; //relayer to message mapping
    mapping(address => bytes) private _relayerToMetadata; //relayer to metadata mapping
    mapping(address => bool) public watchers; //watcher statuses configured by owner
    IInterchainSecurityModule public currentModule; //currently configured ISM
    address[] public watchersArray; //array of configured wactehrs

    // ============ Fraud Variables ============
    mapping(bytes => uint256) public fraudWindows; //message to uint (time duration) to be initiated by initiateFraudWindow()
    mapping(IInterchainSecurityModule => uint256) public subModuleFlagCount; //the number of times a module has been marked fraudulent
    mapping(bytes => uint256) public messageFlagCount; //the number of times a module has been marked fraudulent
    mapping(address => mapping(IInterchainSecurityModule => bool))
        public watcherAlreadyFlaggedModule; //watcher address => submodule => hasFlaggedFraudulent mapping
    mapping(address => mapping(bytes => bool))
        public watcherAlreadyFlaggedMessage; //watcher address => submodule => hasFlaggedFraudulent mapping
    uint256 public mValueToWarrantFraudulence; //the number of flags, denoted by the owner, required to warrant either a submodule or message fraudulent
    uint256 public fraudWindow; //fraud window duration as defined by owner in deployment OR after via changeFraudWindow()

    // ============ Security Variables ============
    bool public mutex; //used in calls to external contracts

    // ============ Custom Errors ============
    error NotWatcher(address attemptedAccess);
    error ISMDoesntExist(bytes message);
    error NotAContract(uint32 _domain, IInterchainSecurityModule _module);
    error DifferentLengthOfArrayInputs(
        address[] _watchersArray,
        bool[] _statuses
    );

    // ============ Modifiers ============
    modifier onlyWatcher() {
        if (!watchers[msg.sender]) {
            revert NotWatcher(msg.sender);
        }
        _;
    }

    // ============ Constructor ============
    constructor(
        uint32 _domain,
        IInterchainSecurityModule _module,
        uint256 _fraudWindow,
        uint256 _mValue
    ) {
        _set(_domain, _module);
        fraudWindow = _fraudWindow;
        mValueToWarrantFraudulence = _mValue;
        //call staticMofNAddressSetFactory to generate Watchers.sol implementation
    }

    // ============ Internal/Private Functions ============

    /**
     * @notice sets ISM to be used in message verification
     * @param _domain origin domain of the ISM
     * @param _module ISM module to use for verification
     */
    function _set(uint32 _domain, IInterchainSecurityModule _module) internal {
        if (!Address.isContract(address(_module))) {
            revert NotAContract(_domain, _module);
        }
        _submodule[_domain] = _module;
        currentModule = _module;
    }

    /**
     * @notice opens a fraud window in which watchers can mark submodules as fraudulent
     */
    function _initiateFraudWindow(bytes calldata _message) internal {
        fraudWindows[_message] = block.timestamp;
    }

    /**
     * @notice checks to see if the fraud window is still open
     * @param _message formatted Hyperlane message (see Message.sol) mapped to fraud window
     */
    function _checkFraudWindow(bytes memory _message)
        internal
        view
        returns (bool)
    {
        if (block.timestamp > fraudWindows[_message] + fraudWindow) {
            return true;
        } else {
            return false;
        }
    }

    // ============ External/Public Functions ============

    /**
     * @notice allows owner to define M value when considering the number of flags required to define fraudulence
     * @param _mValue time duration of new fraud window
     */
    function defineMValue(uint256 _mValue) public onlyOwner {
        mValueToWarrantFraudulence = _mValue;
        emit MValueChanged(_mValue);
    }

    /**
     * @notice allows owner to modify current fraud window duration
     * @param _newFraudWindow time duration of new fraud window
     */
    function changeFraudWindow(uint256 _newFraudWindow) external onlyOwner {
        fraudWindow = _newFraudWindow;
        emit FraudWindowChanged(_newFraudWindow);
    }

    /**
     * @notice checks to see if:
     * 1	The message sent has not been flagged as compromised by m-of-n watchers
     * 2	The submodule used has not been flagged as compromised by m-of-n watchers
     * 3	The fraud window has elapsed
     */
    function preVerifiedCheck() internal view returns (bool) {
        bytes memory message = _relayerToMessages[msg.sender];
        bool flagsForSubModulesPass = assessIfMOfNWatchersHaveFlaggedSubmoduleAsFraudulent(
                message
            );
        bool flagsForMessagesPass = assessIfMOfNWatchersHaveFlaggedMessageAsFraudulent(
                message
            );
        if (
            relayers[msg.sender] &&
            flagsForSubModulesPass &&
            flagsForMessagesPass &&
            _checkFraudWindow(message)
        ) {
            return true;
        }
    }

    /**
     * @notice allows owner to modify ISM being used for message verification
     * @param _domain origin domain of the ISM
     * @param _module alternative ISM module to be used
     */
    function setIsm(uint32 _domain, IInterchainSecurityModule _module)
        external
        onlyOwner
    {
        _set(_domain, _module);
        currentModule = _module;
        emit SubmoduleChanged(_module);
    }

    /**
     * @notice returns the ISM responsible for verifying _message
     * @dev changes based on the content of _message
     * @param _message formatted Hyperlane message (see Message.sol).
     * @return module ISM being used to verify _message
     */
    function submodule(bytes memory _message)
        public
        view
        override
        returns (IInterchainSecurityModule)
    {
        IInterchainSecurityModule module = messageToSubmodule[_message];
        return module;
    }

    /**
     * @notice allows owner to add/modify watchers in watchers mapping
     * @param _watchersArray array of watcher addresses
     * @param _statuses correlating statuses of watchers being added/modified
     */
    function configureWatchers(
        address[] memory _watchersArray,
        bool[] memory _statuses
    ) public onlyOwner {
        if (_watchersArray.length != _statuses.length) {
            revert DifferentLengthOfArrayInputs(_watchersArray, _statuses);
        }
        for (uint8 i = 0; i < _watchersArray.length; i++) {
            watchers[_watchersArray[i]] = _statuses[i];
        }
    }

    /**
     * @notice allows watchers added by owner to flag ISM submodule(s) as fraudulent
     * @param _message formatted Hyperlane message (see Message.sol).
     */
    function flagSubmoduleAsFraudulent(bytes calldata _message)
        public
        onlyWatcher
    {
        IInterchainSecurityModule thisModule = submodule(_message);
        if (!watcherAlreadyFlaggedModule[msg.sender][thisModule]) {
            subModuleFlagCount[thisModule]++;
            watcherAlreadyFlaggedModule[msg.sender][thisModule] = true;
        }
        emit SubmoduleFlaggedFraudulent(thisModule, msg.sender);
    }

    /**
     * @notice allows watchers added by owner to flag messages as fraudulent
     * @param _message message to be marked as fraudulent
     */
    function flagMessageAsFraudulent(bytes memory _message) public onlyWatcher {
        // messagesToFraudFlags[_message] = true;
        if (!watcherAlreadyFlaggedMessage[msg.sender][_message]) {
            messageFlagCount[_message]++;
            watcherAlreadyFlaggedMessage[msg.sender][_message] = true;
        }
    }

    /**
     * @notice returns boolean evaluating if mOfN watchers have flagged a submnodule as fraudulent
     * @param _message message to be used in checks
     */
    function assessIfMOfNWatchersHaveFlaggedSubmoduleAsFraudulent(
        bytes memory _message
    ) public view returns (bool) {
        IInterchainSecurityModule thisModule = submodule(_message);
        if (subModuleFlagCount[thisModule] > mValueToWarrantFraudulence) {
            return true;
        }
    }

    /**
     * @notice returns boolean evaluating if mOfN watchers have flagged a message as fraudulent
     * @param _message message to be used in checks
     */
    function assessIfMOfNWatchersHaveFlaggedMessageAsFraudulent(
        bytes memory _message
    ) public view returns (bool) {
        if (messageFlagCount[_message] > mValueToWarrantFraudulence) {
            return true;
        }
    }

    // ============ Core Functionality ============

    /**
     * @notice outsources verification logic to the configured submodule
     * @param _metadata arbitrary bytes that can be specified by an off-chain relayer, used in message verification
     * @param  _message formatted Hyperlane message (see Message.sol).
     */
    function verify(bytes memory _metadata, bytes memory _message)
        public
        returns (bool)
    {
        bool verified = IInterchainSecurityModule(currentModule).verify(
            _metadata,
            _message
        );
        return verified;
    }

    /**
     * @notice recieves and stores message and metadata sent by a relayer,
     *         adding their addresses to the relayers mapping,
     *         initiating a fraudWindow, mapping the message to this fraudWindow and
     *         mapping the message sent to the submodule used to verify the message
     * @param  _metadata arbitrary bytes that can be specified by an off-chain relayer, used in message verification
     * @param  _message formatted Hyperlane message (see Message.sol).
     */
    function preVerify(bytes calldata _metadata, bytes calldata _message)
        public
        override
        returns (bool)
    {
        _relayerToMessages[msg.sender] = _message;
        // messagesToFraudFlags[_message] = false;
        _relayerToMetadata[msg.sender] = _metadata;
        _initiateFraudWindow(_message);
        emit FraudWindowOpened(currentModule);
        emit RelayerCalledMessagePreVerify(msg.sender);
        return true;
    }

    /**
     * @notice calls preVerifiedCheck() to ensure the submodule has not been flagged as fraudulent
     *         and, if preVerifiedCheck() returns true, verifies the message and
     *         delivers it to the destination address
     * @param  _destination destination for message sent by relayer (msg.sender)
     */
    function deliver(address _destination) public {
        bytes storage message = _relayerToMessages[msg.sender];
        bytes storage metadata = _relayerToMetadata[msg.sender];
        mutex = false;
        if (!mutex) {
            mutex = true;
            bool isVerified = verify(metadata, message);
            if (isVerified) {
                bool verifiedMessagePassesChecks = preVerifiedCheck();
                if (verifiedMessagePassesChecks) {
                    Address.functionCall(_destination, message);
                    emit MessageDelivered(message);
                }
            }
            mutex = false;
        }
    }
}

//////////////////////////////////////////////////////////////////////////////////////////////////
/*
@dev
notes on contract architecture;
    1   This architecture runs on the premise that each relayer can only send 1 message at a time 
            through the OptimisticISM
    2   What if a submodule has been modified after it has been pre-verified? 
    3   All trust is put in the hands of watchers, who don't seem to be incentivised at this stage.
    4   Any and all watchers can flag submodules as fraudulent
    5   The removeWatchers() functionality will leave redundant watcher addresses in place, potentially 
            causing overflow issues with time
    6   Message delivery on line 154 assumes that the receiver's fallback function contains the logic 
            to process the interchain message
    7   What degree of privacy each operator (owner) of the OptimisticIsm wants is unclear. For the sake
            of security and clarity, all modifications to message, submodule state and fraudulence have been 
            included as events
 */
//////////////////////////////////////////////////////////////////////////////////////////////////
