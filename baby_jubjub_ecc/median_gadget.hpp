//
// Created by svasilyev on 10/24/18.
//

#ifndef BABY_JUBJUB_ECC_MEDIAN_GADGET_HPP
#define BABY_JUBJUB_ECC_MEDIAN_GADGET_HPP

namespace libsnark {

    template<typename FieldT, typename HashT>
    class median_gadget : public gadget<FieldT> {
    private:
        std::vector<eddsa<FieldT, HashT>> signature_verifiers;
        std::vector<pb_variable<FieldT>> packed_messages;
        std::vector<packing_gadget<FieldT>> packers;
        pb_variable_array<FieldT> less;
        pb_variable_array<FieldT> less_or_eq;
        std::vector<comparison_gadget<FieldT>> comparators;

    public:
        const size_t n;

        pb_variable<FieldT> median;

        pb_variable<FieldT> a;
        pb_variable<FieldT> d;
        pb_variable<FieldT> base_x;
        pb_variable<FieldT> base_y;

        std::vector<pb_variable_array<FieldT>> pk_x_bins;
        std::vector<pb_variable_array<FieldT>> pk_y_bins;
        std::vector<pb_variable_array<FieldT>> r_x_bins;
        std::vector<pb_variable_array<FieldT>> r_y_bins;
        std::vector<pb_variable_array<FieldT>> ss;
        std::vector<pb_variable_array<FieldT>> ms;

        median_gadget(protoboard<FieldT> &pb,
                      const size_t n,
                      const pb_variable<FieldT> &median,
                      const std::vector<pb_variable_array<FieldT>> &pk_x_bins,
                      const std::vector<pb_variable_array<FieldT>> &pk_y_bins,
                      const std::vector<pb_variable_array<FieldT>> &r_x_bins,
                      const std::vector<pb_variable_array<FieldT>> &r_y_bins,
                      const std::vector<pb_variable_array<FieldT>> &ss,
                      const std::vector<pb_variable_array<FieldT>> &ms);

        void generate_r1cs_constraints();

        void generate_r1cs_witness();
    };
}

#endif //BABY_JUBJUB_ECC_MEDIAN_GADGET_HPP
