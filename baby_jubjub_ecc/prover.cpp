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
#include "oracle_protoboard.hpp"
#include "wraplibsnark.cpp"


using namespace libsnark;
typedef sha256_ethereum HashT;


libff::bit_vector from_binary_string(std::string s) {
    libff::bit_vector v;
    for (auto b : s) {
        v.emplace_back(b == '1');
    }
    return v;
}


int main() {
    typedef libff::alt_bn128_pp ppT;
    typedef libff::Fr<ppT> FieldT;

    ppT::init_public_params();

    const size_t n = 1;

    oracle_protoboard<FieldT, HashT> pb(n);

    std::ifstream file("keys/signature");
    std::string S_bin, message_bin, pk_x_bin, pk_y_bin, r_x_bin, r_y_bin;
    file >> S_bin >> message_bin >> pk_x_bin >> pk_y_bin >> r_x_bin >> r_y_bin;
    pb.ss[0].fill_with_bits(pb, from_binary_string(S_bin));
    pb.ms[0].fill_with_bits(pb, from_binary_string(message_bin));
    pb.pk_x_bins[0].fill_with_bits(pb, from_binary_string(pk_x_bin));
    pb.pk_y_bins[0].fill_with_bits(pb, from_binary_string(pk_y_bin));
    pb.r_x_bins[0].fill_with_bits(pb, from_binary_string(r_x_bin));
    pb.r_y_bins[0].fill_with_bits(pb, from_binary_string(r_y_bin));

    pb.generate_r1cs_constraints();
    pb.generate_r1cs_witness();

    std::cout << "Median: " << pb.val(pb.median) << std::endl;

    assert(pb.is_satisfied());

    r1cs_gg_ppzksnark_zok_proving_key<ppT> pk;
    std::ifstream pk_dump("keys/pk.libsnark");
    pk_dump >> pk;

    r1cs_gg_ppzksnark_zok_verification_key<ppT> vk;
    std::ifstream vk_dump("keys/vk.libsnark");
    vk_dump >> vk;

    r1cs_gg_ppzksnark_zok_processed_verification_key<ppT> pvk;
    std::ifstream pvk_dump("keys/pvk.libsnark");
    pvk_dump >> pvk;

    libff::print_header("R1CS GG-ppzkSNARK Prover");
    r1cs_gg_ppzksnark_zok_proof<ppT> proof = r1cs_gg_ppzksnark_zok_prover<ppT>(pk, pb.primary_input(), pb.auxiliary_input());
    printf("\n"); libff::print_indent(); libff::print_mem("after prover");

    std::vector<FieldT> public_input;
    public_input.emplace_back(123);
    for (auto b : from_binary_string(pk_x_bin + pk_y_bin)) {
        public_input.emplace_back(b);
    }

    std::cout << "Median: " << public_input[0] << std::endl;

    libff::print_header("R1CS GG-ppzkSNARK Verifier");
    const bool ans = r1cs_gg_ppzksnark_zok_verifier_strong_IC<ppT>(vk, public_input, proof);
    printf("\n"); libff::print_indent(); libff::print_mem("after verifier");
    printf("* The verification result is: %s\n", (ans ? "PASS" : "FAIL"));

    libff::print_header("R1CS GG-ppzkSNARK Online Verifier");
    const bool ans2 = r1cs_gg_ppzksnark_zok_online_verifier_strong_IC<ppT>(pvk, public_input, proof);
    assert(ans == ans2);

    std::cout << "Total constraints: " << pb.num_constraints() << std::endl;

    return 0;
}
