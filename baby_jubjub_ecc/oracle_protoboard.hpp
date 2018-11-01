//
// Created by swasilyev on 10/31/18.
//

#ifndef BABY_JUBJUB_ECC_ORACLE_PROTOBOARD_HPP
#define BABY_JUBJUB_ECC_ORACLE_PROTOBOARD_HPP

#include <depends/libsnark/libsnark/gadgetlib1/protoboard.hpp>
#include "median_gadget.hpp"

namespace libsnark {

    template<typename FieldT, typename HashT>
    class oracle_protoboard : public protoboard<FieldT> {

    public:
        const size_t n;
        protoboard<FieldT> pb;
        pb_variable<FieldT> median;
        pb_variable_array<FieldT> pks_packed;
        pb_variable_array<FieldT> pks_unpacked;
        std::vector<pb_variable_array<FieldT>> pk_x_bins;
        std::vector<pb_variable_array<FieldT>> pk_y_bins;
        std::vector<pb_variable_array<FieldT>> r_x_bins;
        std::vector<pb_variable_array<FieldT>> r_y_bins;
        std::vector<pb_variable_array<FieldT>> ss;
        std::vector<pb_variable_array<FieldT>> ms;

        std::shared_ptr<median_gadget<FieldT, HashT>> _median_gadget;
        std::shared_ptr<multipacking_gadget<FieldT>> pks_packer;

        oracle_protoboard(const size_t n);

        void generate_r1cs_constraints();

        void generate_r1cs_witness();
    };
}

#include "oracle_protoboard.cpp"

#endif //BABY_JUBJUB_ECC_ORACLE_PROTOBOARD_HPP
