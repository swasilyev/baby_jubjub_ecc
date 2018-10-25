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
#include "libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp" //hold key
#include "baby_jubjub.hpp"
#include "eddsa.hpp"
#include "pedersen_commitment.hpp"
#include "median_gadget.cpp"


using namespace libsnark;
typedef sha256_ethereum HashT;


libff::bit_vector from_binary_string(std::string s) {
    libff::bit_vector v;
    for (auto b : s)
        v.push_back(b == '1');
    return v;
}


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

    std::ifstream file("tests/signature");
    std::string S_bin, message_bin, pk_x_bin, pk_y_bin, r_x_bin, r_y_bin;
    file >> S_bin >> message_bin >> pk_x_bin >> pk_y_bin >> r_x_bin >> r_y_bin;
    ss[0].fill_with_bits(pb, from_binary_string(S_bin));
    ms[0].fill_with_bits(pb, from_binary_string(message_bin));
    pk_x_bins[0].fill_with_bits(pb, from_binary_string(pk_x_bin));
    pk_y_bins[0].fill_with_bits(pb, from_binary_string(pk_y_bin));
    r_x_bins[0].fill_with_bits(pb, from_binary_string(r_x_bin));
    r_y_bins[0].fill_with_bits(pb, from_binary_string(r_y_bin));

    median_gadget<FieldT, HashT> x(pb, 1, median, pk_x_bins, pk_y_bins, r_x_bins, r_y_bins, ss, ms);
    x.generate_r1cs_constraints();
    x.generate_r1cs_witness();

    assert(pb.is_satisfied());
    std::cout << pb.num_constraints() << std::endl;

    return 0;
}
