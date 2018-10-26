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
#include <depends/libsnark/libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
#include "libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp" //hold key
#include "baby_jubjub.hpp"
#include "eddsa.hpp"
#include "pedersen_commitment.hpp"
#include "median_gadget.cpp"


using namespace libsnark;
typedef sha256_ethereum HashT;


int main() {
    typedef libff::alt_bn128_pp ppT;
    typedef libff::Fr<ppT> FieldT;

    ppT::init_public_params();

    const size_t n = 1;

    protoboard<FieldT> pb;

    pb_variable<FieldT> median;
    median.allocate(pb, "median");

    std::vector<pb_variable_array<FieldT>> pk_x_bins(n);
    std::vector<pb_variable_array<FieldT>> pk_y_bins(n);
    for (size_t i = 0; i < n; i++) {
        pk_x_bins[i].allocate(pb, 256, "pk_x_bin_" + i);
        pk_y_bins[i].allocate(pb, 256, "pk_y_bin_" + i);
    }

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

    median_gadget<FieldT, HashT> x(pb, 1, median, pk_x_bins, pk_y_bins, r_x_bins, r_y_bins, ss, ms);
    x.generate_r1cs_constraints();

    const size_t public_input_size = 1 + n * 2 * 256;
    pb.set_input_sizes(public_input_size); // median + n public keys

    libff::print_header("R1CS GG-ppzkSNARK Generator");
    r1cs_ppzksnark_keypair<ppT> keypair = r1cs_ppzksnark_generator<ppT>(pb.get_constraint_system());
    printf("\n");
    libff::print_indent();
    libff::print_mem("after generator");

    libff::print_header("Preprocess verification key");
    r1cs_ppzksnark_processed_verification_key<ppT> pvk = r1cs_ppzksnark_verifier_process_vk<ppT>(keypair.vk);

    std::ofstream pk_dump("pk");
    pk_dump << keypair.pk;

    std::ofstream vk_dump("vk");
    vk_dump << keypair.vk;

    std::ofstream pvk_dump("pvk");
    pvk_dump << pvk;

    std::cout << "Total constraints: " << pb.num_constraints() << std::endl;

    return 0;
}
