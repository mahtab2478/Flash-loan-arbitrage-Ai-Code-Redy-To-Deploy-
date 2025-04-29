// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {FlashLoanSimpleReceiverBase} from "@aave/core-v3/contracts/flashloan/base/FlashLoanSimpleReceiverBase.sol";
import {IPoolAddressesProvider} from "@aave/core-v3/contracts/interfaces/IPoolAddressesProvider.sol";
import {IERC20} from "@aave/core-v3/contracts/dependencies/openzeppelin/contracts/IERC20.sol";
import {SafeERC20} from "@aave/core-v3/contracts/dependencies/openzeppelin/contracts/SafeERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Pausable} from "@openzeppelin/contracts/security/Pausable.sol";

interface IDexRouter {
    function swapExactTokensForTokens(
        uint amountIn,
        uint amountOutMin,
        address[] calldata path,
        address to,
        uint deadline
    ) external returns (uint[] memory amounts);

    function getAmountsOut(
        uint amountIn, 
        address[] memory path
    ) external view returns (uint[] memory amounts);
}

contract SecurePolygonArbitrage is FlashLoanSimpleReceiverBase, ReentrancyGuard, Ownable, Pausable {
    using SafeERC20 for IERC20;

    struct DexConfig {
        address router;
        uint24 poolFee;
        bool enabled;
        string name;
    }

    struct ArbitragePath {
        address[] path;
        uint256 expectedOutput;
        address dexRouter;
        uint256 dexFee;
    }

    // Token Addresses (Polygon Mainnet)
    address public constant USDC = 0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174;
    address public constant WETH = 0x7ceB23fD6bC0adD59E62ac25578270cFf1b9f619;
    address public constant DAI = 0x8f3Cf7ad23Cd3CaDbD9735AFf958023239c6A063;

    // Configuration
    uint256 public minProfitThreshold = 1500000000000000000; // 1.5 USDC (adjusted for decimals)
    uint256 public slippageTolerance = 30; // 0.3% in basis points
    uint256 public feePercentage = 20; // 0.2% in basis points
    address public profitWallet = 0x519212b1De291E2C55f223aB23D69e895d08545b;
    uint256 public maxLoanAmount = 1000000000000000000000000; // $1M USDC
    uint256 public deadlineExtension = 300; // 5 minutes
    uint256 public cooldownPeriod = 60; // 1 minute
    bool public usePrivateRPC = true;
    
    // DEX Configurations
    mapping(address => DexConfig) public dexConfigurations;
    address[] public supportedDexes;

    // State
    bool public circuitBreakerActive;
    uint256 public lastExecutionTime;
    mapping(address => bool) public approvedTokens;
    mapping(address => uint256) public tokenMinProfits;

    event FlashLoanExecuted(address indexed token, uint256 amount, uint256 fee);
    event ArbitrageProfit(address indexed token, uint256 profit);
    event CircuitBreakerTriggered(bool active);
    event SlippageExceeded(uint256 expected, uint256 actual);
    event LiquidityCheckFailed(address dex, address token);
    event DexAdded(address indexed router, uint24 fee, bool enabled, string name);
    event DexUpdated(address indexed router, bool enabled);
    event PrivateRPCToggled(bool enabled);
    event SlippageUpdated(uint256 newTolerance);
    event MinProfitThresholdUpdated(uint256 newThreshold);
    event TokenAdded(address indexed token, uint256 minProfit);
    event TokenRemoved(address indexed token);
    event ProfitWalletUpdated(address newWallet);
    event MaxLoanAmountUpdated(uint256 newAmount);
    event CooldownUpdated(uint256 newCooldown);
    event DeadlineExtensionUpdated(uint256 newExtension);

    constructor(
        address _aavePoolAddressProvider
    ) FlashLoanSimpleReceiverBase(IPoolAddressesProvider(_aavePoolAddressProvider)) Ownable(msg.sender) {
        // Initialize approved tokens with min profit thresholds
        _addToken(USDC, minProfitThreshold);
        _addToken(WETH, minProfitThreshold);
        _addToken(DAI, minProfitThreshold);

        // Initialize DEX configurations
        _addDex(0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45, 3000, true, "Uniswap V3");
        _addDex(0x1b02dA8Cb0d097eB8D57A175b88c7D8b47997506, 3000, true, "SushiSwap");
        _addDex(0xa5E0829CaCEd8fFDD4De3c43696c57F7D7A678ff, 3000, true, "QuickSwap");
    }

    function _addToken(address token, uint256 minProfit) internal {
        require(token != address(0), "Invalid token address");
        approvedTokens[token] = true;
        tokenMinProfits[token] = minProfit;
        emit TokenAdded(token, minProfit);
    }

    function _addDex(address router, uint24 fee, bool enabled, string memory name) internal {
        require(router != address(0), "Invalid router address");
        dexConfigurations[router] = DexConfig(router, fee, enabled, name);
        supportedDexes.push(router);
        emit DexAdded(router, fee, enabled, name);
    }

    modifier onlyWhenReady() {
        require(!paused(), "Contract is paused");
        require(!circuitBreakerActive, "Circuit breaker active");
        require(block.timestamp >= lastExecutionTime + cooldownPeriod, "In cooldown");
        _;
    }

    /**
     * @notice Execute arbitrage with specified paths
     */
    function executeArbitrage(
        address token,
        uint256 amount,
        ArbitragePath[] calldata paths,
        uint256 deadline
    ) external onlyOwner nonReentrant whenNotPaused {
        require(approvedTokens[token], "Token not approved");
        require(amount <= maxLoanAmount, "Amount exceeds max");
        require(block.timestamp <= deadline, "Deadline passed");
        require(paths.length > 0, "No paths provided");
        
        // Verify liquidity across all paths
        for (uint i = 0; i < paths.length; i++) {
            _verifyLiquidity(paths[i]);
        }

        lastExecutionTime = block.timestamp;
        POOL.flashLoanSimple(address(this), token, amount, abi.encode(paths), 0);
    }

    function executeOperation(
        address asset,
        uint256 amount,
        uint256 premium,
        address initiator,
        bytes calldata params
    ) external override nonReentrant returns (bool) {
        require(initiator == address(this), "Unauthorized");
        require(!circuitBreakerActive, "Circuit breaker active");

        ArbitragePath[] memory paths = abi.decode(params, (ArbitragePath[]));
        uint256 balanceBefore = IERC20(asset).balanceOf(address(this));
        
        // Execute multi-path arbitrage
        for (uint i = 0; i < paths.length; i++) {
            _executeTradeWithProtection(paths[i]);
        }

        // Profit verification
        uint256 totalDebt = amount + premium;
        uint256 balanceAfter = IERC20(asset).balanceOf(address(this));
        uint256 profit = balanceAfter - balanceBefore;
        
        require(profit >= tokenMinProfits[asset], "Profit below threshold");
        require(
            balanceAfter >= totalDebt + (totalDebt * slippageTolerance) / 10000,
            "Slippage too high"
        );

        // Approve repayment
        IERC20(asset).approve(address(POOL), totalDebt);
        
        // Handle profits
        if (profit > 0) {
            uint256 fee = (profit * feePercentage) / 10000;
            if (fee > 0) {
                IERC20(asset).safeTransfer(profitWallet, fee);
                profit -= fee;
            }
            IERC20(asset).safeTransfer(owner(), profit);
            emit ArbitrageProfit(asset, profit);
        }

        return true;
    }

    function _executeTradeWithProtection(ArbitragePath memory path) internal {
        IERC20 tokenIn = IERC20(path.path[0]);
        uint256 amountIn = tokenIn.balanceOf(address(this));
        
        tokenIn.safeApprove(path.dexRouter, amountIn);
        
        uint256 minAmountOut = path.expectedOutput - 
                             (path.expectedOutput * slippageTolerance) / 10000;
        
        uint256[] memory amounts = IDexRouter(path.dexRouter).swapExactTokensForTokens(
            amountIn,
            minAmountOut,
            path.path,
            address(this),
            block.timestamp + deadlineExtension
        );
        
        if (amounts[amounts.length - 1] < minAmountOut) {
            emit SlippageExceeded(minAmountOut, amounts[amounts.length - 1]);
            revert("Slippage too high");
        }
    }

    function _verifyLiquidity(ArbitragePath memory path) internal view {
        require(dexConfigurations[path.dexRouter].enabled, "DEX not enabled");
        
        try IDexRouter(path.dexRouter).getAmountsOut(
            path.expectedOutput,
            path.path
        ) returns (uint256[] memory amounts) {
            require(amounts[amounts.length - 1] > 0, "Insufficient liquidity");
        } catch {
            revert("Liquidity check failed");
        }
    }

    // ========== ADMIN FUNCTIONS ========== //
    function addDex(address router, uint24 fee, bool enabled, string memory name) external onlyOwner {
        _addDex(router, fee, enabled, name);
    }

    function updateDex(address router, bool enabled) external onlyOwner {
        require(dexConfigurations[router].router != address(0), "DEX not found");
        dexConfigurations[router].enabled = enabled;
        emit DexUpdated(router, enabled);
    }

    function addToken(address token, uint256 minProfit) external onlyOwner {
        _addToken(token, minProfit);
    }

    function removeToken(address token) external onlyOwner {
        require(approvedTokens[token], "Token not approved");
        delete approvedTokens[token];
        delete tokenMinProfits[token];
        emit TokenRemoved(token);
    }

    function setTokenMinProfit(address token, uint256 minProfit) external onlyOwner {
        require(approvedTokens[token], "Token not approved");
        tokenMinProfits[token] = minProfit;
    }

    function setSlippageTolerance(uint256 tolerance) external onlyOwner {
        require(tolerance <= 500, "Max 5% slippage allowed");
        slippageTolerance = tolerance;
        emit SlippageUpdated(tolerance);
    }

    function setMinProfitThreshold(uint256 threshold) external onlyOwner {
        minProfitThreshold = threshold;
        emit MinProfitThresholdUpdated(threshold);
    }

    function setFeePercentage(uint256 fee) external onlyOwner {
        require(fee <= 1000, "Max 10% fee allowed");
        feePercentage = fee;
    }

    function setProfitWallet(address wallet) external onlyOwner {
        require(wallet != address(0), "Invalid wallet address");
        profitWallet = wallet;
        emit ProfitWalletUpdated(wallet);
    }

    function setMaxLoanAmount(uint256 amount) external onlyOwner {
        maxLoanAmount = amount;
        emit MaxLoanAmountUpdated(amount);
    }

    function setCooldownPeriod(uint256 cooldown) external onlyOwner {
        cooldownPeriod = cooldown;
        emit CooldownUpdated(cooldown);
    }

    function setDeadlineExtension(uint256 extension) external onlyOwner {
        deadlineExtension = extension;
        emit DeadlineExtensionUpdated(extension);
    }

    function togglePrivateRPC(bool enabled) external onlyOwner {
        usePrivateRPC = enabled;
        emit PrivateRPCToggled(enabled);
    }

    function activateCircuitBreaker() external onlyOwner {
        circuitBreakerActive = true;
        emit CircuitBreakerTriggered(true);
    }

    function resetCircuitBreaker() external onlyOwner {
        circuitBreakerActive = false;
        emit CircuitBreakerTriggered(false);
    }

    function emergencyWithdraw(address token) external onlyOwner {
        IERC20(token).safeTransfer(owner(), IERC20(token).balanceOf(address(this)));
    }

    function getSupportedDexes() external view returns (DexConfig[] memory) {
        DexConfig[] memory dexes = new DexConfig[](supportedDexes.length);
        for (uint i = 0; i < supportedDexes.length; i++) {
            dexes[i] = dexConfigurations[supportedDexes[i]];
        }
        return dexes;
    }

    function getApprovedTokens() external pure returns (address[] memory) {
        address[] memory tokens = new address[](3);
        tokens[0] = USDC;
        tokens[1] = WETH;
        tokens[2] = DAI;
        return tokens;
    }

    receive() external payable {
        revert("MATIC not accepted");
    }
}
