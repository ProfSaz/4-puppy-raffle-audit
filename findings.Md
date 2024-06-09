### [S-N] TITLE (Root Cause + Impact)

**Description:**

**Impact:**

**Proof Of Concept:**

**Recommended Mitigation:**

### [M-N] Looping through players array to check for duplicate in `PuppyRaffle::enterRaffle` is a potential Denial of Service attack (DoS), incrementing gas cost for future entrant 

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


### [S-N] TITLE (Root Cause + Impact)

**Description:**

**Impact:**

**Proof Of Concept:**

**Recommended Mitigation:**

## [L-2] Solidity pragma should be specific, not wide

Consider using a specific version of Solidity in your contracts instead of a wide version. For example, instead of `pragma solidity ^0.8.0;`, use `pragma solidity 0.8.0;`

<details><summary>1 Found Instances</summary>


- Found in src/PuppyRaffle.sol [Line: 2](src/PuppyRaffle.sol#L2)

	```solidity
	pragma solidity ^0.7.6;
	```

</details>