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
#include "median_gadget.cpp"
#include "export.cpp"


using namespace libsnark;
typedef sha256_ethereum HashT;


int main() {
    typedef libff::alt_bn128_pp ppT;
    typedef libff::Fr<ppT> FieldT;

    ppT::init_public_params();

    const size_t n = 1;

    protoboard<FieldT> pb;

    // Protoboard is a... kinda protoboard. Here we define the inputs and connect (constraint) them using gadgets.

    // Public inputs are always first.
    pb_variable<FieldT> median;
    median.allocate(pb, "median");

    std::vector<pb_variable_array<FieldT>> pk_x_bins(n);
    std::vector<pb_variable_array<FieldT>> pk_y_bins(n);
    for (size_t i = 0; i < n; i++) {
        pk_x_bins[i].allocate(pb, 256, "pk_x_bin_" + i);
        pk_y_bins[i].allocate(pb, 256, "pk_y_bin_" + i);
    }

    // And these are our private inputs. Note that besides the inputs we provide the values for,
    // gadgets are free to introduce additional
    std::vector<pb_variable_array<FieldT>> r_x_bins(n);
    std::vector<pb_variable_array<FieldT>> r_y_bins(n);
    std::vector<pb_variable_array<FieldT>> ss(n);
    std::vector<pb_variable_array<FieldT>> ms(n);
    for (size_t i = 0; i < n; i++) {
        r_x_bins[i].allocate(pb, 256, "r_x_bin_" + i);
        r_y_bins[i].allocate(pb, 256, "r_y_bin_" + i);
        ss[i].allocate(pb, 256, "s_" + i);
        ms[i].allocate(pb, 256, "m_" + i);
    }

    // Here comes the gadget. We "connect" it to our inputs, so that it will constraint them
    // (maybe through some additional inputs it encapsulates).
    median_gadget<FieldT, HashT> x(pb, 1, median, pk_x_bins, pk_y_bins, r_x_bins, r_y_bins, ss, ms);

    // The things that are important for key generation are inputs and constraints. Values are not.

    x.generate_r1cs_constraints();

    const size_t public_input_size = 1 + n * 2 * 256; // median + n public keys (points on the curve)
    pb.set_input_sizes(public_input_size); // Which inputs are public is also important.

    libff::print_header("R1CS GG-ppzkSNARK Generator");
    r1cs_gg_ppzksnark_zok_keypair<ppT> keypair = r1cs_gg_ppzksnark_zok_generator<ppT>(pb.get_constraint_system());
    printf("\n");
    libff::print_indent();
    libff::print_mem("after generator");

    libff::print_header("Preprocess verification key");
    r1cs_gg_ppzksnark_zok_processed_verification_key<ppT> pvk = r1cs_gg_ppzksnark_zok_verifier_process_vk<ppT>(keypair.vk);

    // We dump the keys in libsnark format. pk is required to the prover, vks -- for the verifier
    // By the way reading the pk from disk is not that faster than generating it.
    // So we will need to make the prover generate proofs online.

    std::ofstream pk_dump("keys/pk");
    pk_dump << keypair.pk;

    std::ofstream vk_dump("keys/vk");
    vk_dump << keypair.vk;

    std::ofstream pvk_dump("keys/pvk");
    pvk_dump << pvk;

    // And also in json that will be used to instantiate the verifier smart contract
//    vk2json(keypair, "keys/vk.json");

    std::cout << "Total constraints: " << pb.num_constraints() << std::endl;

    return 0;
}
