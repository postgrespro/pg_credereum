pragma solidity ^0.4.19;

contract HashStorage
{
	address						owner;
	mapping(uint => uint256)	hashes;
	uint						lastHashId;

	constructor() public
	{
		owner = msg.sender;
	}

	function saveHash(uint256 hash) public
	{
		if (msg.sender == owner)
			hashes[++lastHashId] = hash;
	}

	function getHash(uint id) public view returns (uint256 hash)
	{
		return hashes[id];
	}

	function getLastHashId() public view returns (uint id)
	{
		return lastHashId;
	}
}
