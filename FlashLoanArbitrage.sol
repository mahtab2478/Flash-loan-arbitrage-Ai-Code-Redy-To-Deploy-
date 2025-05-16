// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {FlashLoanSimpleReceiverBase} from "@aave/core-v3/contracts/flashloan/base/FlashLoanSimpleReceiverBase.sol";
import {IPoolAddressesProvider} from "@aave/core-v3/contracts/interfaces/IPoolAddressesProvider.sol";
import {IERC20, SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Permit.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/security/Pausable.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";

// Chainlink Price Feed Interface
interface IChainlinkAggregator {
    function latestRoundData() external view returns (
        uint80 roundId,
        int256 answer,
        uint256 startedAt,
        uint256 updatedAt,
        uint80 answeredInRound
    );
    function getAnswer(uint256 roundId) external view returns (int256);
}

interface IUniswapV2Router {
    function swapExactTokensForTokens(
        uint amountIn,
        uint amountOutMin,
        address[] calldata path,
        address to,
        uint deadline
    ) external returns (uint[] memory amounts);
    
    function getAmountsOut(uint amountIn, address[] memory path) external view returns (uint[] memory amounts);
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);
}

interface IUniswapV3Router {
    struct ExactInputParams {
        bytes path;
        address recipient;
        uint256 deadline;
        uint256 amountIn;
        uint256 amountOutMinimum;
    }
    
    function exactInput(ExactInputParams calldata params) external payable returns (uint256 amountOut);
}

contract FlashLoanArbitrage is FlashLoanSimpleReceiverBase, ReentrancyGuard, Pausable {
    using SafeERC20 for IERC20;
    
    // Configurable parameters
    address public constant AAVE_POOL_ADDRESSES_PROVIDER = 0xa97684ead0e402dC232d5A977953DF7ECBaB3CDb;
    address public owner;
    address private constant FLASHBOTS_BUILDER = 0x1f9090aaE28b8a3dCeaDf281B0F12828e676c326;
    
    // DEX configuration
    struct DexConfig {
        address router;
        bool isV3;
        uint24 poolFee; // Only for V3
    }
    
    DexConfig[] public dexConfigs;
    address[] public supportedTokens;
    
    // MEV protection
    address public mevBlocker;
    bool public usePrivateTransactions;
    
    // Profit parameters
    uint256 public feePercentage = 5; // 0.5%
    uint256 public minProfitThreshold = 1500 * 1e6; // $1500 in 6 decimals
    uint256 public maxSlippage = 20; // 2%
    uint256 public maxPriceImpact = 30; // 3%
    
    // Contract state
    uint256 public maxTxLimit = 1000000 * 1e6; // Max transaction limit
    
    // Multi-sig addresses
    address[] public multiSigWalletAddresses;
    struct Approval {
        uint256 approvals;
        mapping(address => bool) approved;
    }
    mapping(bytes32 => Approval) private multiSigApprovals;
    
    // Emergency withdrawal
    uint256 public constant EMERGENCY_DELAY = 2 days;
    uint256 public emergencyWithdrawalInitiated;
    address public emergencyWithdrawalToken;
    uint256 public emergencyWithdrawalAmount;
    
    // Dynamic fee structure
    struct TieredFee {
        uint256 minProfit;
        uint256 feePercentage;
    }
    TieredFee[] public feeTiers;
    
    // Chainlink price feed
    IChainlinkAggregator public priceFeed;
    
    // Events
    event ArbitrageExecuted(
        address[] path,
        uint256 profit,
        uint256 timestamp,
        bool thresholdMet
    );
    event ArbitrageFailed(
        address[] path,
        uint256 expectedProfit,
        uint256 actualProfit,
        string reason,
        uint256 timestamp
    );
    event FlashLoanReceived(address indexed token, uint256 amount, uint256 fee);
    event ConfigUpdated();
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event SwapExecuted(address indexed router, uint256 amountIn, uint256 amountOut);
    event EmergencyWithdraw(address indexed token, uint256 amount);
    event EmergencyWithdrawInitiated(address indexed token, uint256 amount);
    event GasCostLogged(uint256 gasUsed);
    event SlippageWarning(uint256 slippage);
    event ProfitTracked(uint256 profit);
    event TransactionReversed(string reason);
    
    // Structs
    struct ArbitragePath {
        address[] path;
        address[] routers;
        bool[] isV3;
        uint24[] poolFees;
    }
    
    struct ExecutionParams {
        uint256 amount;
        uint256 minProfit;
        uint256 deadline;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    modifier protectedFromMEV() {
        if (usePrivateTransactions) {
            require(
                msg.sender == tx.origin || 
                msg.sender == mevBlocker || 
                msg.sender == FLASHBOTS_BUILDER,
                "MEV protection"
            );
        }
        _;
    }
    
    modifier enforceTxLimit(uint256 amount) {
        require(amount <= maxTxLimit, "Transaction exceeds limit");
        _;
    }

    constructor(address _priceFeedAddress) FlashLoanSimpleReceiverBase(IPoolAddressesProvider(AAVE_POOL_ADDRESSES_PROVIDER)) {
        owner = msg.sender;
        priceFeed = IChainlinkAggregator(_priceFeedAddress);
        
        // Initialize with default Polygon routers
        dexConfigs.push(DexConfig(0xa5E0829CaCEd8fFDD4De3c43696c57F7D7A678ff, false, 0)); // QuickSwap V2
        dexConfigs.push(DexConfig(0x1b02dA8Cb0d097eB8D57A175b88c7D8b47997506, false, 0)); // SushiSwap
        dexConfigs.push(DexConfig(0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45, true, 3000)); // Uniswap V3
        
        // Initialize with common Polygon tokens
        supportedTokens.push(0x7ceB23fD6bC0adD59E62ac25578270cFf1b9f619); // WETH
        supportedTokens.push(0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174); // USDC
        supportedTokens.push(0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270); // WMATIC
    }

    // Main arbitrage function
    function startArbitrage(
        ArbitragePath memory path,
        ExecutionParams memory params,
        bytes32 txHash
    ) external onlyOwner nonReentrant whenNotPaused protectedFromMEV enforceTxLimit(params.amount) {
        require(path.path.length >= 2, "Invalid path length");
        require(params.amount > 0, "Amount must be > 0");
        require(params.deadline > block.timestamp, "Deadline passed");
        require(isMultiSigApproved(txHash), "Multi-sig approval required");
        require(path.path.length == path.routers.length + 1, "Path/router mismatch");
        require(path.routers.length == path.isV3.length, "Router/version mismatch");
        require(!path.isV3[0] || path.poolFees.length == path.routers.length, "Missing pool fees");
        
        // Token whitelist check
        for (uint i = 0; i < path.path.length; i++) {
            require(_isSupportedToken(path.path[i]), "Unsupported token");
        }
        
        // Validate path and routers
        for (uint i = 0; i < path.routers.length; i++) {
            require(_isValidRouter(path.routers[i]), "Invalid router");
        }
        
        // Check liquidity and price impact
        _validateLiquidity(path.path[0], params.amount);
        
        // Bundle as atomic operation
        _executeAtomicArbitrage(path, params);
    }

    // Atomic arbitrage execution
    function _executeAtomicArbitrage(
        ArbitragePath memory path,
        ExecutionParams memory params
    ) private {
        bytes memory data = abi.encode(path, params);
        POOL.flashLoanSimple(
            address(this),
            path.path[0],
            params.amount,
            data,
            0
        );
    }

    function executeOperation(
        address asset,
        uint256 amount,
        uint256 premium,
        address initiator,
        bytes calldata params
    ) external override nonReentrant whenNotPaused returns (bool) {
        require(initiator == address(this), "Invalid initiator");
        
        (ArbitragePath memory path, ExecutionParams memory execParams) = 
            abi.decode(params, (ArbitragePath, ExecutionParams));
        
        require(asset == path.path[0], "Invalid initial asset");
        
        emit FlashLoanReceived(asset, amount, premium);

        uint256 gasStart = gasleft();
        
        // Process arbitrage
        uint256 profit = _processArbitrage(path, amount, premium, execParams);
        
        // Log gas usage
        uint256 gasUsed = gasStart - gasleft();
        emit GasCostLogged(gasUsed);
        
        // Repay flash loan
        IERC20(asset).safeApprove(address(POOL), amount + premium);
        
        return true;
    }

    // Core arbitrage logic
    function _processArbitrage(
        ArbitragePath memory path,
        uint256 amount,
        uint256 premium,
        ExecutionParams memory params
    ) private returns (uint256) {
        uint256 initialAmount = amount;
        uint256[] memory amounts = new uint256[](path.path.length);
        amounts[0] = amount;
        
        // Execute swaps along the path
        for (uint i = 0; i < path.path.length - 1; i++) {
            address tokenIn = path.path[i];
            address tokenOut = path.path[i+1];
            
            IERC20(tokenIn).safeApprove(path.routers[i], amounts[i]);
            
            uint256 slippage = getDynamicSlippage();
            emit SlippageWarning(slippage);
            
            if (path.isV3[i]) {
                amounts[i+1] = _swapV3(
                    path.routers[i],
                    tokenIn,
                    tokenOut,
                    amounts[i],
                    path.poolFees[i],
                    params.deadline
                );
            } else {
                amounts[i+1] = _swapV2(
                    path.routers[i],
                    tokenIn,
                    tokenOut,
                    amounts[i],
                    params.deadline
                );
            }
            
            emit SwapExecuted(path.routers[i], amounts[i], amounts[i+1]);
        }
        
        // Final validation
        uint256 finalAmount = amounts[amounts.length - 1];
        uint256 amountOwed = initialAmount + premium;
        require(finalAmount > amountOwed, "No profit");
        
        uint256 profit = finalAmount - amountOwed;
        emit ProfitTracked(profit);
        
        // Check dynamic profit threshold
        if (profit < getDynamicProfitThreshold()) {
            emit ArbitrageFailed(
                path.path,
                params.minProfit,
                profit,
                "Profit threshold not met",
                block.timestamp
            );
            revert("Arbitrage failed: Profit threshold not met");
        }
        
        require(profit >= params.minProfit, "Profit below threshold");
        
        // Take dynamic fee and transfer profit
        uint256 currentFee = getDynamicFee(profit);
        uint256 ownerProfit = profit - (profit * currentFee / 1000);
        IERC20(path.path[0]).safeTransfer(owner, ownerProfit);
        
        emit ArbitrageExecuted(
            path.path,
            ownerProfit,
            block.timestamp,
            profit >= minProfitThreshold
        );
        
        return profit;
    }

    // V2 Swap with slippage protection
    function _swapV2(
        address router,
        address tokenIn,
        address tokenOut,
        uint256 amountIn,
        uint256 deadline
    ) private returns (uint256) {
        address[] memory path = new address[](2);
        path[0] = tokenIn;
        path[1] = tokenOut;
        
        uint256 minAmountOut = _getMinAmountOut(router, amountIn, path);
        
        uint[] memory amounts = IUniswapV2Router(router).swapExactTokensForTokens(
            amountIn,
            minAmountOut,
            path,
            address(this),
            deadline
        );
        
        return amounts[amounts.length - 1];
    }

    // V3 Swap with slippage protection
    function _swapV3(
        address router,
        address tokenIn,
        address tokenOut,
        uint256 amountIn,
        uint24 poolFee,
        uint256 deadline
    ) private returns (uint256) {
        bytes memory path = abi.encodePacked(
            tokenIn,
            poolFee,
            tokenOut
        );
        
        uint256 minAmountOut = _getV3MinAmountOut(amountIn);
        
        IERC20(tokenIn).safeApprove(router, amountIn);
        
        IUniswapV3Router.ExactInputParams memory params = IUniswapV3Router.ExactInputParams({
            path: path,
            recipient: address(this),
            deadline: deadline,
            amountIn: amountIn,
            amountOutMinimum: minAmountOut
        });
        
        return IUniswapV3Router(router).exactInput(params);
    }

    // Dynamic slippage adjustment based on market conditions
    function getDynamicSlippage() public view returns (uint256) {
        (, int256 answer, , uint256 updatedAt, ) = priceFeed.latestRoundData();
        require(block.timestamp - updatedAt < 1 hours, "Stale price data");
        
        // Calculate volatility
        uint256 volatility = _calculateVolatility();
        
        // Base slippage + volatility adjustment
        uint256 dynamicSlippage = maxSlippage + (volatility / 10);
        
        // Cap at reasonable maximum
        return dynamicSlippage > 50 ? 50 : dynamicSlippage;
    }

    function _calculateVolatility() private view returns (uint256) {
        // Get current and previous prices
        uint80 currentRound = priceFeed.latestRound();
        int256 currentPrice = priceFeed.getAnswer(currentRound);
        int256 previousPrice = priceFeed.getAnswer(currentRound - 1);
        
        // Calculate percentage change
        uint256 change = uint256((currentPrice > previousPrice) ? 
            currentPrice - previousPrice : previousPrice - currentPrice);
        return (change * 100) / uint256(previousPrice);
    }

    // Dynamic profit threshold calculation
    function getDynamicProfitThreshold() public view returns (uint256) {
        // Adjust threshold based on market volatility
        int256 price = priceFeed.latestAnswer();
        return minProfitThreshold * uint256(price) / 1e8; // Adjust based on price feed decimals
    }

    // Dynamic fee calculation
    function getDynamicFee(uint256 profit) public view returns (uint256) {
        for (uint i = 0; i < feeTiers.length; i++) {
            if (profit >= feeTiers[i].minProfit) {
                return feeTiers[i].feePercentage;
            }
        }
        return feePercentage; // Default
    }

    // Price and liquidity checks
    function _getMinAmountOut(
        address router,
        uint256 amountIn,
        address[] memory path
    ) private view returns (uint256) {
        uint256 expectedOut = IUniswapV2Router(router).getAmountsOut(amountIn, path)[path.length - 1];
        return expectedOut * (1000 - getDynamicSlippage()) / 1000;
    }
    
    function _getV3MinAmountOut(
        uint256 amountIn
    ) private view returns (uint256) {
        return amountIn * (1000 - getDynamicSlippage()) / 1000;
    }

    function _validateLiquidity(address token, uint256 amount) private view {
        // Check against multiple pools
        uint256 totalLiquidity;
        for (uint i = 0; i < dexConfigs.length; i++) {
            if (!dexConfigs[i].isV3) {
                (uint256 reserveA, uint256 reserveB) = _getPoolReserves(dexConfigs[i].router);
                totalLiquidity += reserveA + reserveB;
            }
        }
        
        require(
            amount <= totalLiquidity / 20, // Max 5% of total liquidity
            "Insufficient liquidity across all pools"
        );
        
        uint256 priceImpact = _calculatePriceImpact(token, amount);
        require(
            priceImpact < maxPriceImpact, 
            string(abi.encodePacked("Price impact too high: ", Strings.toString(priceImpact)))
        );
    }

    // Multi-sig functions
    function isMultiSigApproved(bytes32 txHash) public view returns (bool) {
        Approval storage approval = multiSigApprovals[txHash];
        return approval.approvals >= (multiSigWalletAddresses.length / 2) + 1;
    }

    function approveTransaction(bytes32 txHash) external {
        require(isMultiSigWallet(msg.sender), "Not authorized signer");
        require(!multiSigApprovals[txHash].approved[msg.sender], "Already approved");
        
        multiSigApprovals[txHash].approvals++;
        multiSigApprovals[txHash].approved[msg.sender] = true;
    }

    function isMultiSigWallet(address wallet) public view returns (bool) {
        for (uint i = 0; i < multiSigWalletAddresses.length; i++) {
            if (multiSigWalletAddresses[i] == wallet) {
                return true;
            }
        }
        return false;
    }

    // Emergency withdrawal functions
    function initiateEmergencyWithdraw(address token) external onlyOwner {
        emergencyWithdrawalToken = token;
        emergencyWithdrawalAmount = IERC20(token).balanceOf(address(this));
        emergencyWithdrawalInitiated = block.timestamp;
        emit EmergencyWithdrawInitiated(token, emergencyWithdrawalAmount);
    }

    function completeEmergencyWithdraw() external onlyOwner {
        require(emergencyWithdrawalInitiated > 0, "No withdrawal initiated");
        require(
            block.timestamp >= emergencyWithdrawalInitiated + EMERGENCY_DELAY,
            "Delay not passed"
        );
        
        IERC20(emergencyWithdrawalToken).safeTransfer(
            owner, 
            emergencyWithdrawalAmount
        );
        
        emit EmergencyWithdraw(
            emergencyWithdrawalToken, 
            emergencyWithdrawalAmount
        );
        
        // Reset state
        emergencyWithdrawalInitiated = 0;
        emergencyWithdrawalToken = address(0);
        emergencyWithdrawalAmount = 0;
    }

    // Admin functions
    function addMultiSigAddress(address _address) external onlyOwner {
        multiSigWalletAddresses.push(_address);
        emit ConfigUpdated();
    }
    
    function addDexRouter(address router, bool isV3, uint24 poolFee) external onlyOwner {
        dexConfigs.push(DexConfig(router, isV3, poolFee));
        emit ConfigUpdated();
    }
    
    function addSupportedToken(address token) external onlyOwner {
        supportedTokens.push(token);
        emit ConfigUpdated();
    }
    
    function setMevBlocker(address _mevBlocker, bool _usePrivate) external onlyOwner {
        mevBlocker = _mevBlocker;
        usePrivateTransactions = _usePrivate;
        emit ConfigUpdated();
    }
    
    function setProfitParams(
        uint256 _feePercentage,
        uint256 _minProfit,
        uint256 _slippage,
        uint256 _priceImpact
    ) external onlyOwner {
        require(_feePercentage <= 50, "Max 5% fee");
        require(_slippage <= 100, "Max 10% slippage");
        require(_priceImpact <= 100, "Max 10% price impact");
        
        feePercentage = _feePercentage;
        minProfitThreshold = _minProfit;
        maxSlippage = _slippage;
        maxPriceImpact = _priceImpact;
        emit ConfigUpdated();
    }

    function setFeeTiers(TieredFee[] memory tiers) external onlyOwner {
        delete feeTiers;
        for (uint i = 0; i < tiers.length; i++) {
            feeTiers.push(tiers[i]);
        }
        emit ConfigUpdated();
    }
    
    function setMaxTxLimit(uint256 _limit) external onlyOwner {
        maxTxLimit = _limit;
        emit ConfigUpdated();
    }
    
    function pause() external onlyOwner {
        _pause();
    }
    
    function unpause() external onlyOwner {
        _unpause();
    }
    
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Invalid address");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    // Helper functions
    function _isValidRouter(address router) private view returns (bool) {
        for (uint i = 0; i < dexConfigs.length; i++) {
            if (dexConfigs[i].router == router) {
                return true;
            }
        }
        return false;
    }
    
    function _isSupportedToken(address token) private view returns (bool) {
        for (uint i = 0; i < supportedTokens.length; i++) {
            if (supportedTokens[i] == token) {
                return true;
            }
        }
        return false;
    }
    
    function _calculatePriceImpact(address token, uint256 amount) private view returns (uint256) {
        return amount * 10000 / IERC20(token).totalSupply();
    }
    
    function _getPoolReserves(address router) private view returns (uint256, uint256) {
        (uint112 reserve0, uint112 reserve1,) = IUniswapV2Router(router).getReserves();
        return (uint256(reserve0), uint256(reserve1));
    }
    
    // Gas optimizations
    function _safeApprove(
        IERC20 token,
        address spender,
        uint256 amount
    ) private {
        (bool success, bytes memory data) = address(token).call(
            abi.encodeWithSelector(IERC20.approve.selector, spender, amount)
        );
        require(success && (data.length == 0 || abi.decode(data, (bool))), "Approve failed");
    }
    
    // Gas fee estimation
    function estimateGasFee() public view returns (uint256) {
        return gasleft() * tx.gasprice;
    }
    
    // View functions
    function getSupportedTokens() external view returns (address[] memory) {
        return supportedTokens;
    }
    
    function getDexConfigs() external view returns (DexConfig[] memory) {
        return dexConfigs;
    }
    
    function estimateProfit(
        ArbitragePath memory /*path*/,
        uint256 amountIn
    ) external view returns (uint256 estimatedProfit, bool profitable) {
        estimatedProfit = amountIn * 5 / 1000; // 0.5% estimate
        profitable = estimatedProfit >= minProfitThreshold;
    }

    // Fallback function for handling incoming ETH
    receive() external payable {}
}
