/*    
    copyright 2018 to the baby_jubjub_ecc Authors

    This file is part of baby_jubjub_ecc.

    baby_jubjub_ecc is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    baby_jubjub_ecc is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with baby_jubjub_ecc.  If not, see <https://www.gnu.org/licenses/>.
*/



#include <fstream>
#include <depends/libsnark/libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark_zok/r1cs_gg_ppzksnark_zok.hpp>
#include "libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp" //hold key
#include "baby_jubjub.hpp"
#include "eddsa.hpp"
#include "pedersen_commitment.hpp"
#include "median_gadget.hpp"
#include "ethsnarks/export.cpp"
#include "wraplibsnark.cpp"
#include "oracle_protoboard.hpp"


using namespace libsnark;
typedef sha256_ethereum HashT;


int main() {
    typedef libff::alt_bn128_pp ppT;
    typedef libff::Fr<ppT> FieldT;

    ppT::init_public_params();

    const size_t n = 1;

    oracle_protoboard<FieldT, HashT> pb(n);

    pb.generate_r1cs_constraints();

    libff::print_header("R1CS GG-ppzkSNARK Generator");
    r1cs_gg_ppzksnark_zok_keypair<ppT> keypair = r1cs_gg_ppzksnark_zok_generator<ppT>(pb.get_constraint_system());
    printf("\n");
    libff::print_indent();
    libff::print_mem("after generator");

    libff::print_header("Preprocess verification key");
    r1cs_gg_ppzksnark_zok_processed_verification_key<ppT> pvk = r1cs_gg_ppzksnark_zok_verifier_process_vk<ppT>(keypair.vk);

    std::ofstream pk_dump("keys/pk.libsnark");
    pk_dump << keypair.pk;

    std::ofstream vk_dump("keys/vk.libsnark");
    vk_dump << keypair.vk;

    std::ofstream pvk_dump("keys/pvk.libsnark");
    pvk_dump << pvk;

    serializeProvingKeyToFile(keypair.pk, "keys/pk.zokrates");
    serializeVerificationKeyToFile(keypair.vk, "keys/vk.zokrates");
    exportVerificationKey(keypair);

    ethsnarks::vk2json_file(keypair.vk, "keys/vk.ethsnarks.json");

    std::cout << "Total constraints: " << pb.num_constraints() << std::endl;

    return 0;
}
