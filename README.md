# bnbchain-20221007-analyze
分析bnb chain 2022-10-07 黑客事件


黑客地址的交易：

https://bscscan.com/txs?a=0x489a8756c18c0b8b24ec2a2b9ff3d4d447f79bec&ps=100&p=2


第1,2笔交易：
https://bscscan.com/tx/0xa84f85e1afc3e1b8ed5111ba16e11325f8fc5d6081cb6958becd6a333f6d0d1d

黑客从地址 0x975d9bd9928f398c7e01f6ba236816fa558cd94b 获得100BNB，应该是某个交易所的地址？

第3笔交易：
https://bscscan.com/tx/0x1b7b6b151435b2a1d925e4165ff5ff886d72de54c3bcfb6e0a602033520179a5

兑换了`4.5870157`个`Venus BNB (vBNB)`

> 说明: venus是BNBchain上的defi， https://app.venus.io/

第4笔交易：
https://bscscan.com/tx/0x538af30a9880f9ceb53f128716fc0fef055929b6fbeb9570bdae0682fd4ab3b8
将0.1BNB兑换成WBNB

第5笔交易：为资金转移做准备
https://bscscan.com/tx/0x76fd9bc430311631e499754d59b9f1a8f70ca4b02fd9b198d067ac0cb138d697
授权Venus: vBUSD Token  合约，可以操作黑客地址上的BUSD


第6笔交易: 为资金转移做准备
授权给Venus: vUSDT Token 合约，可以操作黑客地址上的BSC-USD

第7笔交易：为资金转移做准备
授权给Venus: vUSDC Token 合约，可以操作黑客地址上的USDC

第8笔交易：
https://bscscan.com/tx/0xa7eedd357e878cc0c445d38e8ef2b8a69a1f8d5914cb8c6bef4c8f172d76c1fb
添加Venus BNB (vBNB) 币对？
https://bscscan.com/address/0xfd36e2c2a6789db23113685031d7f16329158384
https://bscscan.com/address/0xd3f51e66b87227bbd3831eb78eb218627e145fc2#code


第9、10笔：
https://bscscan.com/tx/0xa0af5ab59035b924bb13853ec7ede75ecdb180269038a1fe82c9ac8d25225fb8
兑换WBNB，并进行授权，允许WBNB合约在ibBUSD中交易

第11笔：
https://bscscan.com/tx/0xa4e9bb0ec4dc3b6925e8f6f4329536aee0a0c7e78c0301f486ca843e3a881838
调用ibBUSD 的work函数

第12笔：
https://bscscan.com/tx/0xc7f90ab55374fbb97cb7b9e1364f198bf538ab9f46d1476aea09ac8d52ee0372
 向Venus: vBUSD借了15BUSD

第13笔：
https://bscscan.com/tx/0xde61cd28289b06bd7fe60a29ec5e229188d8f091f89cae585c0841eaa45442b8
授权Stargate Finance: Router 可以操作BUSD


第14笔：进行跨链兑换测试
通过stargate进行跨链：https://stargate.finance/
BSC：https://bscscan.com/tx/0xe83050fefadd55d2e9c72bfeacc334b28e1116506f2af256e1ed986929d2d292
ETH：


至此，准备工作已完成。黑客发现还多出0.1BNB，于是又充了0.1BNB到交易所。黑客当时的心理可能是：“粒粒皆辛苦，不能浪费，万一失手也不能留给币安。”
这就好比，地上有10个亿，和1毛钱，先捡起1毛钱再捡起10个亿。
https://bscscan.com/tx/0xb64a99866ba0c727482919ceee149b761005c4d40c11dc1676ad02cad9cb5d57
---



注册成为中继器（发送100BNB）
https://bscscan.com/tx/0xe1fe5fef26e93e6389910545099303e4fee774427d9e628d2aab80f1b53396d6




攻击核心交易，从系统获取了`1,000,000` BNB
https://bscscan.com/tx/0xebf83628ba893d35b496121fb8201666b8e09f3cbadf0e269162baa72efe3b8b

调用了`CrossChain`的函数 `handlePackage(bytes payload, bytes proof, uint64 height, uint64 packageSequence, uint8 channelId)`


然后将BNB转为Venus: vBNB Token, 为资金跨链做准备
https://bscscan.com/tx/0xf9d911624b5294652ec7f0b9fa7817f2a5953860411325e7f6e73d87f14a70ab

然后有借成 62,500,000 BUSD，
https://bscscan.com/tx/0xbda0344dc9c96bbc5cab60bae8c7622195e68c392cf45f64ecb7c8c5806dd3be

又借了50,000,000 BSC-USD：
https://bscscan.com/tx/0x049ba44ab978687b26f8d45d48b446f5db30ae9c47d77dce6ec11124cb5758ff

然后授权BSC-USD可以在Stargate Finance: Router中交易
https://bscscan.com/tx/0xdf96502f2fb0ce1441c3925a71cbc330b48498ddd4508516f4e1ba58ce764070


开始跨链兑换： 两次  50,000,000 BSC-USD
https://bscscan.com/tx/0x79067c22ab23cc142a59f82641a6d634474780fc54c985286317b2626499eec5
https://bscscan.com/tx/0xeea253e5fb3380120f6d16a520b861fc40632cb9a31c9fb30d562e1a92e2de42




# 代码分析

核心函数就是`handlePackage`

```solidity
function handlePackage(bytes calldata payload, bytes calldata proof, uint64 height, uint64 packageSequence, uint8 channelId) onlyInit onlyRelayer
      sequenceInOrder(packageSequence, channelId) blockSynced(height) channelSupported(channelId) external {
    bytes memory payloadLocal = payload; // fix error: stack too deep, try removing local variables
    bytes memory proofLocal = proof; // fix error: stack too deep, try removing local variables
    require(MerkleProof.validateMerkleProof(ILightClient(LIGHT_CLIENT_ADDR).getAppHash(height), STORE_NAME, generateKey(packageSequence, channelId), payloadLocal, proofLocal), "invalid merkle proof");
```


调用`MerkleProof.validateMerkleProof`， 这里 `merkle proof` 是由预编译合约实现:

```solidity
 uint256[1] memory result;
    /* solium-disable-next-line */
    assembly {
    // call validateMerkleProof precompile contract
    // Contract address: 0x65
      if iszero(staticcall(not(0), 0x65, input, length, result, 0x20)) {}
    }
```

其中 `0x65`就是merkle proof预编译合约地址，



根据bsc的`core/vm/contracts.go`代码

```go

// PrecompiledContractsIstanbul contains the default set of pre-compiled Ethereum
// contracts used in the Istanbul release.
var PrecompiledContractsIstanbul = map[common.Address]PrecompiledContract{
	common.BytesToAddress([]byte{1}): &ecrecover{},
	common.BytesToAddress([]byte{2}): &sha256hash{},
	common.BytesToAddress([]byte{3}): &ripemd160hash{},
	common.BytesToAddress([]byte{4}): &dataCopy{},
	common.BytesToAddress([]byte{5}): &bigModExp{},
	common.BytesToAddress([]byte{6}): &bn256AddIstanbul{},
	common.BytesToAddress([]byte{7}): &bn256ScalarMulIstanbul{},
	common.BytesToAddress([]byte{8}): &bn256PairingIstanbul{},
	common.BytesToAddress([]byte{9}): &blake2F{},

	common.BytesToAddress([]byte{100}): &tmHeaderValidate{},
	common.BytesToAddress([]byte{101}): &iavlMerkleProofValidate{},
}

```

`0x65`即 `101`， 即`iavlMerkleProofValidate`


`iavlMerkleProofValidate`的实现：


```go

// tmHeaderValidate implemented as a native contract.
type iavlMerkleProofValidate struct{}

func (c *iavlMerkleProofValidate) RequiredGas(input []byte) uint64 {
	return params.IAVLMerkleProofValidateGas
}

// input:
// | payload length | payload    |
// | 32 bytes       |            |
func (c *iavlMerkleProofValidate) Run(input []byte) (result []byte, err error) {
	//return nil, fmt.Errorf("suspend")
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("internal error: %v\n", r)
		}
	}()

	if uint64(len(input)) <= precompileContractInputMetaDataLength {
		return nil, fmt.Errorf("invalid input: input should include %d bytes payload length and payload", precompileContractInputMetaDataLength)
	}

	payloadLength := binary.BigEndian.Uint64(input[precompileContractInputMetaDataLength-uint64TypeLength : precompileContractInputMetaDataLength])
	if uint64(len(input)) != payloadLength+precompileContractInputMetaDataLength {
		return nil, fmt.Errorf("invalid input: input size should be %d, actual the size is %d", payloadLength+precompileContractInputMetaDataLength, len(input))
	}

	kvmp, err := lightclient.DecodeKeyValueMerkleProof(input[precompileContractInputMetaDataLength:])
	if err != nil {
		return nil, err
	}

	valid := kvmp.Validate()
	if !valid {
		return nil, fmt.Errorf("invalid merkle proof")
	}

	result = make([]byte, merkleProofValidateResultLength)
	binary.BigEndian.PutUint64(result[merkleProofValidateResultLength-uint64TypeLength:], 0x01)
	return result, nil
}
```






# cosmos/iavl关于BUG的修复

> https://github.com/cosmos/iavl/pull/582/files#diff-8900a93a6d474bd8973beabf67b04383bde602d3bf747ac747eaaae531bcf889




