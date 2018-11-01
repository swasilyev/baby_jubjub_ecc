pragma solidity ^0.4.24;

import "truffle/Assert.sol";
import "../contracts/Verifier.sol";

contract TestVerifier
{
	function testVerifyProof () public
	{
		Verifier.ProofWithInput memory pwi;
		_getStaticProof(pwi);

		Verifier.VerifyingKey memory vk;
		_getVerifyingKey(vk);

		Assert.isTrue(Verifier.Verify(vk, pwi), "Verification failed");
	}

	function _getVerifyingKey (Verifier.VerifyingKey memory vk)
		internal pure
	{
		vk.beta = Pairing.G2Point([0x8951d4289e4eefeb51c9c503b2b997f894c282aa77eef75bd7f2d21b989b18c, 0x197504bd402ab265b7481905f1a1a8b69ecc5e5798320b8a1b77147f30949f1f], [0x2943e20cfe102964d6499bda71912ed866f856586a42bc4d17e64ebd9f8b92c2, 0x129041dc43e334e6a99cc580c77337223fc68d2c576be791c24288863c4f07fa]);
		vk.gamma = Pairing.G2Point([0x259d3abc7a9dc338c0b05f2002612cfde528fa4379761ec7f50a91151a51b620, 0x9e0dfd0379c0ff1b405fe30422835fbdd2d798a2e31eff897ad5c537e0094da], [0x2b72f47097a1b8c5abcfa6859b081402a6b7953127df6d8674ddbbad70f019b6, 0x2ec2d63ca20958a2ee2a2bea1668ac786549b67d28e732c2ca4a96d3c1471081]);
		vk.delta = Pairing.G2Point([0x1cd7ff30feb8be9275f5e1ecb3fd3a68908ab82ddc927c58cf931e2c99c64638, 0xf2c51129c36f9640df7e5d2204f206d78376198a9f3152811bf45ef41fab8cd], [0x1453c22cebb2a3f777ec0fa76fb1c88549dd4cee99a8861fa662090a8f858c03, 0x9fd22d3d34a3545888c05c44ce78150dcb951ebc5e44d74dcbcc3b4e864ef85]);
		vk.alpha = Pairing.G1Point(0x10abd7402965f2b9eed853e58645c8a235e2ef54282d7c0432b4389c55a5dd7a, 0x28ff8702b29cc9b7f93c833894cff1a281efa5e6e5fa981702c82be95fca7840);
		vk.gammaABC = new Pairing.G1Point[](5);
		vk.gammaABC[0] = Pairing.G1Point(0x2ea2173b23b306b760beb377d03ebe031f0dfeeeb967add0891b116913c7c424, 0x56c023671520153c257194738b8635741385e0ace31ad0e9014ea51bbe69088);
		vk.gammaABC[1] = Pairing.G1Point(0x1aa3444634621360c7aabb7e8cc787ac45ac8d38bb4e740cec2af163c9475ed5, 0x276b563932e9cdae276e3ee5b9eb0e9118c38a66c5150e5070f3579605a065b6);
		vk.gammaABC[2] = Pairing.G1Point(0x21b0314610b4c9fb59e5b6138edda58d53abbf499b54f4d71562229e401f1c97, 0x9a46fd1b2e2deaaaf7458a6cdb5dcc1b6390556ecf3950e797f4b60bcd07ed5);
		vk.gammaABC[3] = Pairing.G1Point(0x1a78a3f7b356edf6662ee571d020ce10066385a841f29dfdc381e0e05de79b4b, 0x24cf8e768cffbbce6153bfa3ee4de58b11cd6fba06ee6babcbb7d0cb6b4cf11b);
		vk.gammaABC[4] = Pairing.G1Point(0x12617d188a7ecf3604ee945f89a8d1f53e2f0e4443c79dabf91c8387f762b86b, 0xed2c6ffd83da313d8b8159f038e52a77b5bc54244bcee2c05b91fbeca305f63);
	}

	function _getStaticProof (Verifier.ProofWithInput memory output)
		internal pure
	{
		Verifier.Proof memory proof = output.proof;
		proof.B = Pairing.G2Point([0xae6fa4c0d319780fd200d9f65b3f50268dc75e6318f5556dadc3785ce700bf9, 0x1ea5218a7ba03631aad651141b1dbf307c3db177d1a70e7a858c5279fce5a96b], [0x11bdc2d9a85bbbaa6d456a1501161974fdb80e31f8f8b993bb415bb68882c20c, 0x35fbf73bbdb9d910ddc4609c21f3a594f2cba98a064406dc0095d52a2849ed]);
		proof.A = Pairing.G1Point(0x59d7201cca66429c4150f226368a22e42655d85e938731d28338216b8c93d27, 0x147c0e0c1a4322e64c9a13811470d283d991f4a4d024def5a2d315f931967acc);
		proof.C = Pairing.G1Point(0x2579a6e39d19c17c9a072094e1755ebdfe8a621c15d0d4b8f7aab79124bc21c6, 0x24510f12257e4a4ec929cf16ece3d1284c0f72777d12daa92b9722636fdec2);
		output.input = new uint256[](4);
		output.input[0] = 0x7b;
		output.input[1] = 0x3b1e6a3fdd985cf911db26aa7003a7e161f586f0785d023b923808cf636a342;
		output.input[2] = 0xb1983e9da4e8649e6dc657239bb6daeeb0f4e64a769d6da58c825cef397d259;
		output.input[3] = 0x4;
	}
}
