const TestContract = artifacts.require("TestContract");

let list_flatten = (l) => {
    return [].concat.apply([], l);
};


let vk_to_flat = (vk) => {
    return [
        list_flatten([
            vk.alpha[0], vk.alpha[1],
            list_flatten(vk.beta),
            list_flatten(vk.gamma),
            list_flatten(vk.delta),
        ]),
        list_flatten(vk.gammaABC)
    ];
};

let proof_to_flat = (proof) => {
    return list_flatten([
        proof.A,
        list_flatten(proof.B),
        proof.C
    ]);
};

contract("TestContract", () => {
    describe("Gro16 verifier", () => {
        it("verifies", async () => {
            let obj = await TestContract.deployed();
            var vk = require('../keys/vk.ethsnarks.json');
            var proof = require('../keys/proof.ethsnarks.json');
            let [vk_flat, vk_flat_IC] = vk_to_flat(vk);
            let test_verify_args = [
                vk_flat,                // (alpha, beta, gamma, delta)
                vk_flat_IC,             // gammaABC[]
                proof_to_flat(proof),   // A B C
                proof.input
            ];
            console.log(test_verify_args);
            let test_verify_result = await obj.TestVerify(...test_verify_args);
            assert.strictEqual(test_verify_result, true);
        });
    });
});
